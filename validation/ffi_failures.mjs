// Test hooks live only in this separately built artifact, never native/ or npm archives.
import { spawnSync } from 'node:child_process';
import { mkdirSync, copyFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { root, sourceIdentity, fileSha256 } from '../scripts/common.mjs';
const source=sourceIdentity();const directory=join(root,'target/ffi-validation');mkdirSync(directory,{recursive:true});mkdirSync(join(root,'.reports'),{recursive:true});
const commands=[['cargo',['build','-p','post-quantum-node','--features','validation-hooks','--release','--frozen','--target-dir',directory]]];
const library=process.platform==='win32'?'post_quantum.dll':process.platform==='darwin'?'libpost_quantum.dylib':'libpost_quantum.so';
const binary=join(directory,'post_quantum.validation.node');const steps=[];
function execute(command,args){const r=spawnSync(command,args,{cwd:root,encoding:'utf8',maxBuffer:16*1024*1024});steps.push({command:[command,...args],exitCode:r.status,stdout:r.stdout,stderr:r.stderr,error:r.error?.message});if(r.status!==0||r.error)throw new Error('FFI validation subprocess failed');}
let passed=false;let error;
try {for(const [command,args]of commands)execute(command,args);copyFileSync(join(directory,'release',library),binary);execute(process.execPath,['--expose-gc','tests/ffi-faults.cjs',binary]);passed=true;}catch(e){error=String(e);}
const report={schemaVersion:1,source,sourceUnchanged:sourceIdentity().sourceSha256===source.sourceSha256,passed,steps,error};report.passed&&=report.sourceUnchanged;if(passed)report.binarySha256=fileSha256(binary);
writeFileSync(join(root,'.reports/ffi-failures.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:report.passed,report:'.reports/ffi-failures.json'}));if(!report.passed)process.exitCode=1;
