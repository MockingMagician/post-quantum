//! Local declarations of the stable Node-API 8 C interface.
//!
//! Written from the public Node-API specification, not generated or vendored.
//! https://nodejs.org/api/n-api.html
#![allow(non_snake_case, dead_code)]
use std::ffi::{c_char, c_void};

macro_rules! handles {
    ($($name:ident => $opaque:ident),+ $(,)?) => { $(
        #[repr(C)]
        pub struct $opaque { _private: [u8; 0] }
        pub type $name = *mut $opaque;
    )+ };
}
handles!(Env => EnvOpaque, Value => ValueOpaque, Reference => RefOpaque,
    CallbackInfo => InfoOpaque, Work => WorkOpaque,
    Scope => ScopeOpaque, Cleanup => CleanupOpaque);
pub type Status = i32;
pub type Callback = unsafe extern "C" fn(Env, CallbackInfo) -> Value;
pub type Finalize = unsafe extern "C" fn(Env, *mut c_void, *mut c_void);
pub type Execute = unsafe extern "C" fn(Env, *mut c_void);
pub type Complete = unsafe extern "C" fn(Env, Status, *mut c_void);
pub type CleanupCallback = unsafe extern "C" fn(Cleanup, *mut c_void);
pub const OK: Status = 0;
pub const UNDEFINED: i32 = 0;
pub const OBJECT: i32 = 6;
pub const FUNCTION: i32 = 7;
pub const UINT8_ARRAY: i32 = 1;
pub const DEFAULT_METHOD: i32 = 1 | 4;
pub const DEFAULT_PROPERTY: i32 = 1 | 2 | 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TypeTag {
    pub lower: u64,
    pub upper: u64,
}
#[repr(C)]
pub struct Property {
    pub utf8name: *const c_char,
    pub name: Value,
    pub method: Option<Callback>,
    pub getter: Option<Callback>,
    pub setter: Option<Callback>,
    pub value: Value,
    pub attributes: i32,
    pub data: *mut c_void,
}
impl Property {
    pub fn method(name: &'static std::ffi::CStr, callback: Callback, data: usize) -> Self {
        Self {
            utf8name: name.as_ptr(),
            name: std::ptr::null_mut(),
            method: Some(callback),
            getter: None,
            setter: None,
            value: std::ptr::null_mut(),
            attributes: DEFAULT_METHOD,
            data: data as *mut c_void,
        }
    }
    pub fn value(name: &'static std::ffi::CStr, value: Value) -> Self {
        Self {
            utf8name: name.as_ptr(),
            name: std::ptr::null_mut(),
            method: None,
            getter: None,
            setter: None,
            value,
            attributes: DEFAULT_PROPERTY,
            data: std::ptr::null_mut(),
        }
    }
}

macro_rules! api {
    ($(fn $name:ident($($argument:ident: $kind:ty),* $(,)?) -> $result:ty;)+) => {
        #[cfg(not(windows))]
        unsafe extern "C" { $(pub fn $name($($argument: $kind),*) -> $result;)+ }
        #[cfg(not(windows))]
        pub fn initialize() -> Result<(), &'static str> { Ok(()) }
        #[cfg(windows)]
        mod windows {
            use super::*;
            use std::sync::OnceLock;
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn GetModuleHandleW(name: *const u16) -> *mut c_void;
                fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
            }
            struct Api { $($name: unsafe extern "C" fn($($kind),*) -> $result,)+ }
            static API: OnceLock<Result<Api, &'static str>> = OnceLock::new();
            pub fn initialize() -> Result<(), &'static str> {
                API.get_or_init(|| {
                    // The executable is Node itself. This borrowed handle is not freed.
                    let module = unsafe { GetModuleHandleW(std::ptr::null()) };
                    if module.is_null() { return Err("Cannot find Node executable"); }
                    Ok(Api { $($name: {
                        let address = unsafe { GetProcAddress(module, concat!(stringify!($name), "\0").as_ptr().cast()) };
                        if address.is_null() { return Err(concat!("Missing Node-API symbol: ", stringify!($name))); }
                        // The public C signature above is the contract of this named export.
                        unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn($($kind),*) -> $result>(address) }
                    },)+ })
                }).as_ref().map(|_| ()).map_err(|error| *error)
            }
            $(pub unsafe fn $name($($argument: $kind),*) -> $result {
                let api = API.get().and_then(|api| api.as_ref().ok()).expect("Node-API initialized before callbacks");
                unsafe { (api.$name)($($argument),*) }
            })+
            pub unsafe fn bootstrap_error(env: Env, message: &std::ffi::CStr) {
                let module = unsafe { GetModuleHandleW(std::ptr::null()) };
                if module.is_null() { return; }
                let address = unsafe { GetProcAddress(module, c"napi_throw_error".as_ptr()) };
                if !address.is_null() {
                    let throw = unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn(Env, *const c_char, *const c_char) -> Status>(address) };
                    unsafe { throw(env, c"ERR_NATIVE_BINDING_UNAVAILABLE".as_ptr(), message.as_ptr()); }
                }
                // If even the bootstrap symbol is absent, the JS loader rejects
                // the empty exports. A partially initialized API is never used.
            }
        }
        #[cfg(windows)] pub use windows::*;
    }
}
api! {
    fn napi_get_version(env: Env, result: *mut u32) -> Status;
    fn napi_get_cb_info(env: Env, info: CallbackInfo, argc: *mut usize, argv: *mut Value, receiver: *mut Value, data: *mut *mut c_void) -> Status;
    fn napi_get_new_target(env: Env, info: CallbackInfo, result: *mut Value) -> Status;
    fn napi_typeof(env: Env, value: Value, result: *mut i32) -> Status;
    fn napi_is_typedarray(env: Env, value: Value, result: *mut bool) -> Status;
    fn napi_get_typedarray_info(env: Env, value: Value, kind: *mut i32, length: *mut usize, data: *mut *mut c_void, backing: *mut Value, offset: *mut usize) -> Status;
    fn napi_is_arraybuffer(env: Env, value: Value, result: *mut bool) -> Status;
    fn napi_is_detached_arraybuffer(env: Env, value: Value, result: *mut bool) -> Status;
    fn napi_get_named_property(env: Env, object: Value, name: *const c_char, result: *mut Value) -> Status;
    fn napi_get_global(env: Env, result: *mut Value) -> Status;
    fn napi_create_function(env: Env, name: *const c_char, length: usize, callback: Option<Callback>, data: *mut c_void, result: *mut Value) -> Status;
    fn napi_call_function(env: Env, receiver: Value, function: Value, count: usize, args: *const Value, result: *mut Value) -> Status;
    fn napi_create_string_utf8(env: Env, text: *const c_char, length: usize, result: *mut Value) -> Status;
    fn napi_create_error(env: Env, code: Value, message: Value, result: *mut Value) -> Status;
    fn napi_throw(env: Env, error: Value) -> Status;
    fn napi_throw_error(env: Env, code: *const c_char, message: *const c_char) -> Status;
    fn napi_is_exception_pending(env: Env, result: *mut bool) -> Status;
    fn napi_get_and_clear_last_exception(env: Env, result: *mut Value) -> Status;
    fn napi_get_undefined(env: Env, result: *mut Value) -> Status;
    fn napi_get_boolean(env: Env, value: bool, result: *mut Value) -> Status;
    fn napi_create_uint32(env: Env, value: u32, result: *mut Value) -> Status;
    fn napi_get_value_uint32(env: Env, value: Value, result: *mut u32) -> Status;
    fn napi_create_buffer_copy(env: Env, length: usize, bytes: *const c_void, copied: *mut *mut c_void, result: *mut Value) -> Status;
    fn napi_create_object(env: Env, result: *mut Value) -> Status;
    fn napi_strict_equals(env: Env, left: Value, right: Value, result: *mut bool) -> Status;
    fn napi_define_properties(env: Env, object: Value, length: usize, descriptors: *const Property) -> Status;
    fn napi_define_class(env: Env, name: *const c_char, length: usize, constructor: Option<Callback>, data: *mut c_void, count: usize, descriptors: *const Property, result: *mut Value) -> Status;
    fn napi_new_instance(env: Env, constructor: Value, count: usize, args: *const Value, result: *mut Value) -> Status;
    fn napi_create_reference(env: Env, value: Value, count: u32, result: *mut Reference) -> Status;
    fn napi_delete_reference(env: Env, reference: Reference) -> Status;
    fn napi_get_reference_value(env: Env, reference: Reference, result: *mut Value) -> Status;
    fn napi_wrap(env: Env, object: Value, data: *mut c_void, finalize: Option<Finalize>, hint: *mut c_void, reference: *mut Reference) -> Status;
    fn napi_unwrap(env: Env, object: Value, result: *mut *mut c_void) -> Status;
    fn napi_type_tag_object(env: Env, object: Value, tag: *const TypeTag) -> Status;
    fn napi_check_object_type_tag(env: Env, object: Value, tag: *const TypeTag, result: *mut bool) -> Status;
    fn napi_set_instance_data(env: Env, data: *mut c_void, finalize: Option<Finalize>, hint: *mut c_void) -> Status;
    fn napi_get_instance_data(env: Env, result: *mut *mut c_void) -> Status;
    fn napi_create_async_work(env: Env, resource: Value, name: Value, execute: Option<Execute>, complete: Option<Complete>, data: *mut c_void, result: *mut Work) -> Status;
    fn napi_queue_async_work(env: Env, work: Work) -> Status;
    fn napi_delete_async_work(env: Env, work: Work) -> Status;
    fn napi_cancel_async_work(env: Env, work: Work) -> Status;
    fn napi_add_async_cleanup_hook(env: Env, callback: Option<CleanupCallback>, data: *mut c_void, handle: *mut Cleanup) -> Status;
    fn napi_remove_async_cleanup_hook(handle: Cleanup) -> Status;
    fn napi_open_handle_scope(env: Env, result: *mut Scope) -> Status;
    fn napi_close_handle_scope(env: Env, scope: Scope) -> Status;
}
