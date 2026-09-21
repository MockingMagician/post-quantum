//! Ownership and thread boundary for the local Node-API adapter.
use crate::{Key, Output, ffi::*};
use post_quantum_platform::Zeroizing;
use std::{
    cell::Cell,
    ffi::{CStr, c_void},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr::null_mut,
    rc::Rc,
    sync::Mutex,
};

#[cfg(feature = "validation-hooks")]
use std::sync::atomic::{AtomicUsize, Ordering as CounterOrdering};
#[cfg(feature = "validation-hooks")]
static LIVE_ENVS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "validation-hooks")]
static LIVE_KEYS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "validation-hooks")]
static LIVE_JOBS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "validation-hooks")]
pub unsafe fn resources(env: Env) -> Result<Value> {
    let mut object = null_mut();
    check(unsafe { napi_create_object(env, &mut object) })?;
    let properties = [
        Property::value(c"environments", unsafe {
            number(env, LIVE_ENVS.load(CounterOrdering::SeqCst) as u32)
        }?),
        Property::value(c"keys", unsafe {
            number(env, LIVE_KEYS.load(CounterOrdering::SeqCst) as u32)
        }?),
        Property::value(c"jobs", unsafe {
            number(env, LIVE_JOBS.load(CounterOrdering::SeqCst) as u32)
        }?),
    ];
    check(unsafe { napi_define_properties(env, object, properties.len(), properties.as_ptr()) })?;
    Ok(object)
}

pub struct Failure {
    pub code: &'static str,
    pub message: String,
}
pub type Result<T> = std::result::Result<T, Failure>;
impl Failure {
    pub fn new(code: &'static str, message: &str) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
impl From<post_quantum_core::Error> for Failure {
    fn from(error: post_quantum_core::Error) -> Self {
        Self::new(error.code(), &error.to_string())
    }
}
pub fn internal() -> Failure {
    Failure::new("ERR_INTERNAL", "Native operation failed")
}
pub fn invalid() -> Failure {
    Failure::new(
        "ERR_INVALID_ARGUMENT",
        "Invalid native argument or key type",
    )
}
pub fn check(status: Status) -> Result<()> {
    if status == OK {
        Ok(())
    } else {
        Err(internal())
    }
}

// None of these values may be shared with a compute thread. Rc/Cell deliberately
// keep EnvState !Send/!Sync. Async compute owns only its separate Send payload.
pub struct EnvState {
    pub env: Env,
    constructors: Cell<[Reference; 4]>,
    construction: Cell<*mut Construction>,
    promise_constructor: Cell<Reference>,
    promise_construction: Cell<*mut Settlement>,
    promise_token: Cell<usize>,
    next_promise_token: Cell<usize>,
    jobs: Mutex<Vec<Work>>,
    closing: Cell<bool>,
    cleanup: Cell<Cleanup>,
    cleanup_data: Cell<*mut Rc<EnvState>>,
    cleanup_finished: Cell<bool>,
    #[cfg(feature = "validation-hooks")]
    pub fault: Cell<u32>,
}
impl EnvState {
    fn new(env: Env) -> Self {
        #[cfg(feature = "validation-hooks")]
        LIVE_ENVS.fetch_add(1, CounterOrdering::SeqCst);
        Self {
            env,
            constructors: Cell::new([null_mut(); 4]),
            construction: Cell::new(null_mut()),
            promise_constructor: Cell::new(null_mut()),
            promise_construction: Cell::new(null_mut()),
            promise_token: Cell::new(0),
            next_promise_token: Cell::new(1),
            jobs: Mutex::new(Vec::new()),
            closing: Cell::new(false),
            cleanup: Cell::new(null_mut()),
            cleanup_data: Cell::new(null_mut()),
            cleanup_finished: Cell::new(false),
            #[cfg(feature = "validation-hooks")]
            fault: Cell::new(0),
        }
    }
    fn tag(&self, kind: usize) -> TypeTag {
        // The live, uniquely allocated environment address separates independent
        // addon instances. Tags are opaque brands, not cryptographic secrets.
        TypeTag {
            lower: 0x5051_5253_4b45_5900 | kind as u64,
            upper: self as *const Self as usize as u64,
        }
    }
    #[cfg(feature = "validation-hooks")]
    pub fn pending_count(&self) -> usize {
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(feature = "validation-hooks")]
impl Drop for EnvState {
    fn drop(&mut self) {
        LIVE_ENVS.fetch_sub(1, CounterOrdering::SeqCst);
    }
}

pub unsafe fn state(env: Env) -> Result<Rc<EnvState>> {
    let mut raw = null_mut();
    check(unsafe { napi_get_instance_data(env, &mut raw) })?;
    if raw.is_null() {
        return Err(internal());
    }
    // The instance finalizer owns this Box<Rc<_>> until this env shuts down.
    Ok(unsafe { (&*raw.cast::<Rc<EnvState>>()).clone() })
}
unsafe extern "C" fn finalize_state(_: Env, raw: *mut c_void, _: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(raw.cast::<Rc<EnvState>>()));
    }));
}
pub unsafe fn install_state(env: Env) -> Result<Rc<EnvState>> {
    let state = Rc::new(EnvState::new(env));
    let instance = Box::into_raw(Box::new(state.clone()));
    if let Err(error) = check(unsafe {
        napi_set_instance_data(env, instance.cast(), Some(finalize_state), null_mut())
    }) {
        unsafe {
            drop(Box::from_raw(instance));
        }
        return Err(error);
    }
    let hook_data = Box::into_raw(Box::new(state.clone()));
    let mut hook = null_mut();
    if let Err(error) = check(unsafe {
        napi_add_async_cleanup_hook(env, Some(cleanup), hook_data.cast(), &mut hook)
    }) {
        unsafe {
            drop(Box::from_raw(hook_data));
        }
        return Err(error);
    }
    state.cleanup.set(hook);
    state.cleanup_data.set(hook_data);
    let mut global = null_mut();
    let mut constructor = null_mut();
    let mut reference = null_mut();
    check(unsafe { napi_get_global(env, &mut global) })?;
    check(unsafe { napi_get_named_property(env, global, c"Promise".as_ptr(), &mut constructor) })?;
    check(unsafe { napi_create_reference(env, constructor, 1, &mut reference) })?;
    state.promise_constructor.set(reference);
    Ok(state)
}
unsafe extern "C" fn cleanup(_: Cleanup, raw: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { (&*raw.cast::<Rc<EnvState>>()).clone() };
        state.closing.set(true);
        // No registry lock is held across a Node-API call. Running jobs cannot
        // be cancelled; their completion callback is still responsible for Drop.
        let jobs = state.jobs.lock().unwrap_or_else(|e| e.into_inner()).clone();
        for work in jobs {
            unsafe {
                napi_cancel_async_work(state.env, work);
            }
        }
        unsafe {
            finish_cleanup(&state);
        }
    }));
}
unsafe fn finish_cleanup(state: &Rc<EnvState>) {
    if !state.closing.get()
        || !state
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
        || state.cleanup_finished.replace(true)
    {
        return;
    }
    for reference in state.constructors.replace([null_mut(); 4]) {
        if !reference.is_null() {
            unsafe {
                napi_delete_reference(state.env, reference);
            }
        }
    }
    let promise = state.promise_constructor.replace(null_mut());
    if !promise.is_null() {
        unsafe {
            napi_delete_reference(state.env, promise);
        }
    }
    let hook = state.cleanup.replace(null_mut());
    let data = state.cleanup_data.replace(null_mut());
    if !hook.is_null() {
        unsafe {
            napi_remove_async_cleanup_hook(hook);
        }
    }
    // The caller's Rc keeps state alive even if removing the hook lets Node
    // immediately finalize the instance data.
    if !data.is_null() {
        unsafe {
            drop(Box::from_raw(data));
        }
    }
}

pub fn boundary(env: Env, body: impl FnOnce() -> Result<Value>) -> Value {
    // The outer guard also covers translating Rust failures into JS exceptions.
    catch_unwind(AssertUnwindSafe(|| {
        match catch_unwind(AssertUnwindSafe(body)) {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                unsafe {
                    throw(env, error);
                }
                null_mut()
            }
            Err(_) => {
                unsafe {
                    throw(env, internal());
                }
                null_mut()
            }
        }
    }))
    .unwrap_or(null_mut())
}
pub unsafe fn pending(env: Env) -> bool {
    let mut value = false;
    unsafe { napi_is_exception_pending(env, &mut value) == OK && value }
}
pub unsafe fn text(env: Env, value: &str) -> Result<Value> {
    let mut result = null_mut();
    check(unsafe {
        napi_create_string_utf8(env, value.as_ptr().cast(), value.len(), &mut result)
    })?;
    Ok(result)
}
unsafe fn error_value(env: Env, error: &Failure) -> Result<Value> {
    let code = unsafe { text(env, error.code) }?;
    let message = unsafe { text(env, &error.message) }?;
    let mut result = null_mut();
    check(unsafe { napi_create_error(env, code, message, &mut result) })?;
    Ok(result)
}
unsafe fn throw(env: Env, error: Failure) {
    if unsafe { pending(env) } {
        return;
    }
    if let Ok(value) = unsafe { error_value(env, &error) } {
        unsafe {
            napi_throw(env, value);
        }
    } else if !unsafe { pending(env) } {
        unsafe {
            napi_throw_error(
                env,
                c"ERR_INTERNAL".as_ptr(),
                c"Native operation failed".as_ptr(),
            );
        }
    }
}
unsafe fn reject(env: Env, settlement: &Settlement, error: Failure) {
    let value = if unsafe { pending(env) } {
        let mut exception = null_mut();
        if unsafe { napi_get_and_clear_last_exception(env, &mut exception) } != OK {
            return;
        }
        exception
    } else {
        match unsafe { error_value(env, &error) } {
            Ok(value) => value,
            Err(_) => {
                unsafe {
                    throw(env, internal());
                }
                return;
            }
        }
    };
    let _ = unsafe { settlement.finish(value, false) };
}

// Node-API has no way to dispose an unresolved napi_deferred during shutdown.
// Keep ordinary references to the native Promise's resolve/reject functions:
// references can be deleted even after Worker termination forbids running JS.
struct Settlement {
    env: Env,
    resolve: Reference,
    reject: Reference,
}
impl Settlement {
    unsafe fn finish(&self, value: Value, success: bool) -> Result<()> {
        let mut function = null_mut();
        let reference = if success { self.resolve } else { self.reject };
        check(unsafe { napi_get_reference_value(self.env, reference, &mut function) })?;
        let receiver = unsafe { undefined(self.env) }?;
        check(unsafe { napi_call_function(self.env, receiver, function, 1, &value, null_mut()) })
    }
}
impl Drop for Settlement {
    fn drop(&mut self) {
        for reference in [self.resolve, self.reject] {
            if !reference.is_null() {
                unsafe {
                    napi_delete_reference(self.env, reference);
                }
            }
        }
    }
}
unsafe extern "C" fn promise_executor(env: Env, info: CallbackInfo) -> Value {
    boundary(env, || unsafe {
        let args = arguments(env, info)?;
        let state = state(env)?;
        let raw = state.promise_construction.get();
        if raw.is_null() || args.operation != state.promise_token.get() {
            return Err(invalid());
        }
        let settlement = &mut *raw;
        if !settlement.resolve.is_null() || !settlement.reject.is_null() {
            return Err(invalid());
        }
        for value in [args.values[0], args.values[1]] {
            let mut kind = 0;
            check(napi_typeof(env, value, &mut kind))?;
            if kind != FUNCTION {
                return Err(invalid());
            }
        }
        check(napi_create_reference(
            env,
            args.values[0],
            1,
            &mut settlement.resolve,
        ))?;
        check(napi_create_reference(
            env,
            args.values[1],
            1,
            &mut settlement.reject,
        ))?;
        undefined(env)
    })
}
unsafe fn promise(state: &Rc<EnvState>) -> Result<(Value, Settlement)> {
    let env = state.env;
    let mut settlement = Settlement {
        env,
        resolve: null_mut(),
        reject: null_mut(),
    };
    let token = state.next_promise_token.get();
    state
        .next_promise_token
        .set(token.checked_add(1).ok_or_else(internal)?);
    let mut executor = null_mut();
    check(unsafe {
        napi_create_function(
            env,
            c"postQuantumPromise".as_ptr(),
            18,
            Some(promise_executor),
            token as *mut c_void,
            &mut executor,
        )
    })?;
    let mut constructor = null_mut();
    check(unsafe {
        napi_get_reference_value(env, state.promise_constructor.get(), &mut constructor)
    })?;
    struct Reset<'a>(&'a EnvState, *mut Settlement, usize);
    impl Drop for Reset<'_> {
        fn drop(&mut self) {
            self.0.promise_construction.set(self.1);
            self.0.promise_token.set(self.2);
        }
    }
    let _reset = Reset(
        state,
        state.promise_construction.replace(&mut settlement),
        state.promise_token.replace(token),
    );
    let mut promise = null_mut();
    check(unsafe { napi_new_instance(env, constructor, 1, &executor, &mut promise) })?;
    if settlement.resolve.is_null() || settlement.reject.is_null() {
        return Err(internal());
    }
    Ok((promise, settlement))
}
pub unsafe fn undefined(env: Env) -> Result<Value> {
    let mut value = null_mut();
    check(unsafe { napi_get_undefined(env, &mut value) })?;
    Ok(value)
}
pub unsafe fn boolean(env: Env, input: bool) -> Result<Value> {
    let mut value = null_mut();
    check(unsafe { napi_get_boolean(env, input, &mut value) })?;
    Ok(value)
}
pub unsafe fn number(env: Env, input: u32) -> Result<Value> {
    let mut value = null_mut();
    check(unsafe { napi_create_uint32(env, input, &mut value) })?;
    Ok(value)
}
pub struct Arguments {
    pub values: [Value; 4],
    pub receiver: Value,
    pub operation: usize,
}
pub unsafe fn arguments(env: Env, info: CallbackInfo) -> Result<Arguments> {
    let mut values = [null_mut(); 4];
    let mut count = values.len();
    let mut receiver = null_mut();
    let mut data = null_mut();
    check(unsafe {
        napi_get_cb_info(
            env,
            info,
            &mut count,
            values.as_mut_ptr(),
            &mut receiver,
            &mut data,
        )
    })?;
    Ok(Arguments {
        values,
        receiver,
        operation: data as usize,
    })
}
pub unsafe fn copy_bytes(
    env: Env,
    value: Value,
    max: usize,
    limit: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    if value.is_null() {
        return Err(invalid());
    }
    let mut typed = false;
    if unsafe { napi_is_typedarray(env, value, &mut typed) } != OK || !typed {
        return Err(invalid());
    }
    let (mut kind, mut length, mut data, mut backing, mut offset) =
        (0, 0, null_mut(), null_mut(), 0);
    if unsafe {
        napi_get_typedarray_info(
            env,
            value,
            &mut kind,
            &mut length,
            &mut data,
            &mut backing,
            &mut offset,
        )
    } != OK
        || kind != UINT8_ARRAY
    {
        return Err(invalid());
    }
    let mut arraybuffer = false;
    let mut detached = false;
    if unsafe { napi_is_arraybuffer(env, backing, &mut arraybuffer) } != OK
        || !arraybuffer
        || unsafe { napi_is_detached_arraybuffer(env, backing, &mut detached) } != OK
        || detached
    {
        return Err(invalid());
    }
    if length > max {
        return Err(Failure::new(limit, "Input exceeds the supported length"));
    }
    if length == 0 {
        return Ok(Zeroizing::new(Vec::new()));
    }
    if data.is_null() {
        return Err(invalid());
    }
    // Inspection calls above cannot execute JavaScript; shared and detached
    // stores were rejected. No borrowed JS memory or pointer survives this copy.
    Ok(Zeroizing::new(
        unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length) }.to_vec(),
    ))
}
pub unsafe fn option_bytes(
    env: Env,
    options: Value,
    name: &CStr,
    max: usize,
    limit: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    if options.is_null() {
        return Ok(Zeroizing::new(Vec::new()));
    }
    let mut kind = 0;
    check(unsafe { napi_typeof(env, options, &mut kind) })?;
    if kind == UNDEFINED {
        return Ok(Zeroizing::new(Vec::new()));
    }
    if kind != OBJECT {
        return Err(invalid());
    }
    let mut value = null_mut();
    // This may execute a getter. Call it before obtaining any raw byte pointer.
    check(unsafe { napi_get_named_property(env, options, name.as_ptr(), &mut value) })?;
    check(unsafe { napi_typeof(env, value, &mut kind) })?;
    if kind == UNDEFINED {
        return Ok(Zeroizing::new(Vec::new()));
    }
    unsafe { copy_bytes(env, value, max, limit) }
}

struct KeyHandle {
    key: Key,
}
#[cfg(feature = "validation-hooks")]
impl Drop for KeyHandle {
    fn drop(&mut self) {
        LIVE_KEYS.fetch_sub(1, CounterOrdering::SeqCst);
    }
}
struct Construction {
    key: Option<Key>,
    token: Value,
}
struct ConstructionGuard {
    state: Rc<EnvState>,
    previous: *mut Construction,
}
impl Drop for ConstructionGuard {
    fn drop(&mut self) {
        self.state.construction.set(self.previous);
    }
}
unsafe extern "C" fn finalize_key(_: Env, data: *mut c_void, _: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(data.cast::<KeyHandle>()));
    }));
}
unsafe extern "C" fn constructor(env: Env, info: CallbackInfo) -> Value {
    boundary(env, || unsafe {
        let args = arguments(env, info)?;
        let state = state(env)?;
        let mut new_target = null_mut();
        check(napi_get_new_target(env, info, &mut new_target))?;
        if new_target.is_null() || args.operation >= 4 || args.values[0].is_null() {
            return Err(invalid());
        }
        let raw = state.construction.get();
        if raw.is_null() {
            return Err(invalid());
        }
        let construction = &mut *raw;
        let mut matches = false;
        check(napi_strict_equals(
            env,
            args.values[0],
            construction.token,
            &mut matches,
        ))?;
        if !matches {
            return Err(invalid());
        }
        let key = construction.key.take().ok_or_else(invalid)?;
        if key.kind() != args.operation {
            return Err(invalid());
        }
        #[cfg(feature = "validation-hooks")]
        LIVE_KEYS.fetch_add(1, CounterOrdering::SeqCst);
        let mut handle = Box::new(KeyHandle { key });
        check(napi_type_tag_object(
            env,
            args.receiver,
            &state.tag(args.operation),
        ))?;
        check(napi_wrap(
            env,
            args.receiver,
            (&mut *handle as *mut KeyHandle).cast(),
            Some(finalize_key),
            null_mut(),
            null_mut(),
        ))?;
        let _ = Box::into_raw(handle); // ownership moves to Node's finalizer only on success
        Ok(args.receiver)
    })
}
pub unsafe fn register_class(
    state: &Rc<EnvState>,
    name: &'static CStr,
    kind: usize,
    callback: Callback,
) -> Result<Value> {
    let mut descriptors = vec![Property::method(c"export", callback, 20 + kind)];
    if kind == 1 || kind == 3 {
        descriptors.push(Property::method(c"destroy", callback, 30 + kind));
        let mut getter = Property::method(c"destroyed", callback, 40 + kind);
        getter.method = None;
        getter.getter = Some(callback);
        getter.attributes = 4;
        descriptors.push(getter);
    }
    let mut class = null_mut();
    check(unsafe {
        napi_define_class(
            state.env,
            name.as_ptr(),
            name.to_bytes().len(),
            Some(constructor),
            kind as *mut c_void,
            descriptors.len(),
            descriptors.as_ptr(),
            &mut class,
        )
    })?;
    let mut reference = null_mut();
    check(unsafe { napi_create_reference(state.env, class, 1, &mut reference) })?;
    let mut constructors = state.constructors.get();
    constructors[kind] = reference;
    state.constructors.set(constructors);
    Ok(class)
}
pub unsafe fn key(state: &Rc<EnvState>, value: Value, kind: usize) -> Result<Key> {
    if value.is_null() || kind >= 4 {
        return Err(invalid());
    }
    let mut matches = false;
    if unsafe { napi_check_object_type_tag(state.env, value, &state.tag(kind), &mut matches) } != OK
        || !matches
    {
        return Err(invalid());
    }
    let mut raw = null_mut();
    if unsafe { napi_unwrap(state.env, value, &mut raw) } != OK || raw.is_null() {
        return Err(invalid());
    }
    // The per-environment, per-class tag was checked before the pointer cast.
    let handle = unsafe { &*raw.cast::<KeyHandle>() };
    if handle.key.kind() != kind {
        return Err(invalid());
    }
    Ok(handle.key.clone())
}
unsafe fn make_key(state: &Rc<EnvState>, key: Key) -> Result<Value> {
    let kind = key.kind();
    let mut class = null_mut();
    check(unsafe {
        napi_get_reference_value(state.env, state.constructors.get()[kind], &mut class)
    })?;
    let mut token = null_mut();
    check(unsafe { napi_create_object(state.env, &mut token) })?;
    let mut construction = Construction {
        key: Some(key),
        token,
    };
    let raw = &mut construction as *mut Construction;
    let _guard = ConstructionGuard {
        state: state.clone(),
        previous: state.construction.replace(raw),
    };
    let mut result = null_mut();
    // An inaccessible, ordinary JS object brands this one factory call. No Rust
    // pointer is exposed through an External or retained by JavaScript.
    check(unsafe { napi_new_instance(state.env, class, 1, &token, &mut result) })?;
    Ok(result)
}
unsafe fn output(state: &Rc<EnvState>, output: Output) -> Result<Value> {
    let env = state.env;
    match output {
        Output::Bytes(bytes) => {
            let mut value = null_mut();
            check(unsafe {
                napi_create_buffer_copy(
                    env,
                    bytes.len(),
                    bytes.as_ptr().cast(),
                    null_mut(),
                    &mut value,
                )
            })?;
            Ok(value) // bytes is wiped even when Node allocation fails
        }
        Output::Bool(value) => unsafe { boolean(env, value) },
        Output::Unit => unsafe { undefined(env) },
        Output::Key(key) => unsafe { make_key(state, key) },
        Output::Pair(public, private) => {
            let mut object = null_mut();
            check(unsafe { napi_create_object(env, &mut object) })?;
            let public = unsafe { make_key(state, public) }?;
            let private = unsafe { make_key(state, private) }?;
            let properties = [
                Property::value(c"publicKey", public),
                Property::value(c"privateKey", private),
            ];
            check(unsafe {
                napi_define_properties(env, object, properties.len(), properties.as_ptr())
            })?;
            Ok(object)
        }
    }
}

type Operation = Box<dyn FnOnce() -> Result<Output> + Send>;
struct Compute {
    operation: Option<Operation>,
    result: Option<Result<Output>>,
}
struct MainJob {
    state: Rc<EnvState>,
    settlement: Settlement,
    work: Work,
    fault: u32,
}
struct Job {
    compute: Mutex<Compute>,
    main: MainJob,
}
#[cfg(feature = "validation-hooks")]
impl Drop for Job {
    fn drop(&mut self) {
        LIVE_JOBS.fetch_sub(1, CounterOrdering::SeqCst);
    }
}
// Job is intentionally !Send/!Sync: its main control contains Rc and Node handles.
// Node receives its opaque pointer. execute accesses *only* compute, a Sync Mutex;
// complete reclaims the Box only after Node guarantees execute has returned.
unsafe extern "C" fn execute(_: Env, raw: *mut c_void) {
    // The entire callback is guarded, including result storage and destruction.
    // An unexpected outer panic leaves no result, which complete treats as an error.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let compute = unsafe { &(*raw.cast::<Job>()).compute };
        let result = catch_unwind(AssertUnwindSafe(|| {
            let operation = compute
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .operation
                .take()
                .ok_or_else(internal)?;
            operation()
        }))
        .unwrap_or_else(|_| Err(internal()));
        compute.lock().unwrap_or_else(|e| e.into_inner()).result = Some(result);
    }));
}
struct DeleteWork {
    env: Env,
    work: Work,
}
impl Drop for DeleteWork {
    fn drop(&mut self) {
        unsafe {
            napi_delete_async_work(self.env, self.work);
        }
    }
}
struct RemoveMembership {
    state: Rc<EnvState>,
    work: Work,
}
impl Drop for RemoveMembership {
    fn drop(&mut self) {
        self.state
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|work| *work != self.work);
        unsafe {
            finish_cleanup(&self.state);
        }
    }
}
struct Completion {
    // Fields drop in declaration order, also during unwinding: first release the
    // finished Node work, then wipe owned Rust data, then allow env cleanup.
    _delete: DeleteWork,
    job: Box<Job>,
    _membership: RemoveMembership,
}
unsafe extern "C" fn complete(env: Env, status: Status, raw: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // Sole ownership returns here even when Node cancelled queued work.
        let job = unsafe { Box::from_raw(raw.cast::<Job>()) };
        let state = job.main.state.clone();
        let completion = Completion {
            _delete: DeleteWork {
                env,
                work: job.main.work,
            },
            _membership: RemoveMembership {
                state: state.clone(),
                work: job.main.work,
            },
            job,
        };
        let job = &completion.job;
        let result = catch_unwind(AssertUnwindSafe(|| unsafe {
            if state.closing.get() {
                return;
            }
            let mut scope = null_mut();
            if napi_open_handle_scope(env, &mut scope) != OK {
                throw(env, internal());
                return;
            }
            struct CloseScope(Env, Scope);
            impl Drop for CloseScope {
                fn drop(&mut self) {
                    unsafe {
                        napi_close_handle_scope(self.0, self.1);
                    }
                }
            }
            let _scope = CloseScope(env, scope);
            let result = if status != OK || job.main.fault == 4 {
                Err(internal())
            } else {
                job.compute
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .result
                    .take()
                    .unwrap_or_else(|| Err(internal()))
            };
            match result.and_then(|result| output(&state, result)) {
                Ok(value) => {
                    if job.main.settlement.finish(value, true).is_err() {
                        throw(env, internal());
                    }
                }
                Err(error) => reject(env, &job.main.settlement, error),
            }
        }));
        if result.is_err() && !state.closing.get() {
            unsafe {
                reject(env, &job.main.settlement, internal());
            }
        }
        // Completion's independent guards run even if a Rust result destructor
        // panics. No panic may cross this callback's C ABI.
    }));
}
pub unsafe fn submit(
    state: Rc<EnvState>,
    operation: impl FnOnce() -> Result<Output> + Send + 'static,
) -> Result<Value> {
    if state.closing.get() {
        return Err(internal());
    }
    let env = state.env;
    #[cfg(feature = "validation-hooks")]
    let fault = state.fault.replace(0);
    #[cfg(not(feature = "validation-hooks"))]
    let fault = 0;
    if fault == 1 {
        return Err(internal());
    }
    let (promise, settlement) = unsafe { promise(&state) }?;
    let operation: Operation = Box::new(move || {
        #[cfg(feature = "validation-hooks")]
        if fault == 5 {
            panic!("Validation-only worker panic");
        }
        operation()
    });
    #[cfg(feature = "validation-hooks")]
    LIVE_JOBS.fetch_add(1, CounterOrdering::SeqCst);
    let mut job = Box::new(Job {
        compute: Mutex::new(Compute {
            operation: Some(operation),
            result: None,
        }),
        main: MainJob {
            state: state.clone(),
            settlement,
            work: null_mut(),
            fault,
        },
    });
    let name = match unsafe { text(env, "post-quantum:operation") } {
        Ok(name) => name,
        Err(error) => {
            unsafe {
                reject(env, &job.main.settlement, error);
            }
            return Ok(promise);
        }
    };
    let raw = (&mut *job as *mut Job).cast();
    let status = if fault == 2 {
        1
    } else {
        unsafe {
            napi_create_async_work(
                env,
                null_mut(),
                name,
                Some(execute),
                Some(complete),
                raw,
                &mut job.main.work,
            )
        }
    };
    if status != OK {
        unsafe {
            reject(env, &job.main.settlement, internal());
        }
        return Ok(promise);
    }
    state
        .jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(job.main.work);
    let status = if fault == 3 {
        1
    } else {
        unsafe { napi_queue_async_work(env, job.main.work) }
    };
    if status != OK {
        state
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|work| *work != job.main.work);
        unsafe {
            napi_delete_async_work(env, job.main.work);
            reject(env, &job.main.settlement, internal());
        }
        return Ok(promise);
    }
    let _ = Box::into_raw(job); // completion callback now owns this allocation
    Ok(promise)
}
