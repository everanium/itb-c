/*
 * itb_ffi.h — raw libitb C ABI declarations (private to the binding).
 *
 * Mirrors dist/<os>-<arch>/libitb.h's `ITB_*` exports verbatim; copied
 * here so the binding's compile step does not depend on the dist/
 * include path. The signatures below MUST stay bit-identical to libitb's
 * own header; an audit pass diffs the two periodically.
 *
 * Source-of-truth: cmd/cshared/main.go's `//export` comments.
 */
#ifndef ITB_FFI_H
#define ITB_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* ---- Library / introspection -------------------------------------- */
extern int ITB_Version(char *out, size_t cap_bytes, size_t *out_len);
extern int ITB_HashCount(void);
extern int ITB_HashName(int i, char *out, size_t cap_bytes, size_t *out_len);
extern int ITB_HashWidth(int i);
extern int ITB_LastError(char *out, size_t cap_bytes, size_t *out_len);

/* ---- Seed --------------------------------------------------------- */
extern int ITB_NewSeed(char *hash_name, int key_bits, uintptr_t *out_handle);
extern int ITB_FreeSeed(uintptr_t handle);
extern int ITB_SeedWidth(uintptr_t handle, int *out_status);
extern int ITB_SeedHashName(uintptr_t handle, char *out, size_t cap_bytes, size_t *out_len);
extern int ITB_NewSeedFromComponents(char *hash_name, uint64_t *components,
                                     int components_len, uint8_t *hash_key,
                                     int hash_key_len, uintptr_t *out_handle);
extern int ITB_GetSeedHashKey(uintptr_t handle, uint8_t *out, size_t cap_bytes, size_t *out_len);
extern int ITB_GetSeedComponents(uintptr_t handle, uint64_t *out, int cap_count, int *out_len);

/* ---- Cipher (Single + Triple) ------------------------------------- */
extern int ITB_Encrypt(uintptr_t noise, uintptr_t data, uintptr_t start,
                       void *plaintext, size_t pt_len,
                       void *out, size_t out_cap, size_t *out_len);
extern int ITB_Decrypt(uintptr_t noise, uintptr_t data, uintptr_t start,
                       void *ciphertext, size_t ct_len,
                       void *out, size_t out_cap, size_t *out_len);
extern int ITB_Encrypt3(uintptr_t noise,
                        uintptr_t data1, uintptr_t data2, uintptr_t data3,
                        uintptr_t start1, uintptr_t start2, uintptr_t start3,
                        void *plaintext, size_t pt_len,
                        void *out, size_t out_cap, size_t *out_len);
extern int ITB_Decrypt3(uintptr_t noise,
                        uintptr_t data1, uintptr_t data2, uintptr_t data3,
                        uintptr_t start1, uintptr_t start2, uintptr_t start3,
                        void *ciphertext, size_t ct_len,
                        void *out, size_t out_cap, size_t *out_len);

/* ---- MAC ---------------------------------------------------------- */
extern int ITB_MACCount(void);
extern int ITB_MACName(int i, char *out, size_t cap_bytes, size_t *out_len);
extern int ITB_MACKeySize(int i);
extern int ITB_MACTagSize(int i);
extern int ITB_MACMinKeyBytes(int i);
extern int ITB_NewMAC(char *mac_name, void *key, size_t key_len, uintptr_t *out_handle);
extern int ITB_FreeMAC(uintptr_t handle);

extern int ITB_EncryptAuth(uintptr_t noise, uintptr_t data, uintptr_t start, uintptr_t mac,
                           void *plaintext, size_t pt_len,
                           void *out, size_t out_cap, size_t *out_len);
extern int ITB_DecryptAuth(uintptr_t noise, uintptr_t data, uintptr_t start, uintptr_t mac,
                           void *ciphertext, size_t ct_len,
                           void *out, size_t out_cap, size_t *out_len);
extern int ITB_EncryptAuth3(uintptr_t noise,
                            uintptr_t data1, uintptr_t data2, uintptr_t data3,
                            uintptr_t start1, uintptr_t start2, uintptr_t start3,
                            uintptr_t mac,
                            void *plaintext, size_t pt_len,
                            void *out, size_t out_cap, size_t *out_len);
extern int ITB_DecryptAuth3(uintptr_t noise,
                            uintptr_t data1, uintptr_t data2, uintptr_t data3,
                            uintptr_t start1, uintptr_t start2, uintptr_t start3,
                            uintptr_t mac,
                            void *ciphertext, size_t ct_len,
                            void *out, size_t out_cap, size_t *out_len);

/* ---- Process-wide knobs ------------------------------------------ */
extern int ITB_SetBitSoup(int mode);
extern int ITB_GetBitSoup(void);
extern int ITB_SetLockSoup(int mode);
extern int ITB_GetLockSoup(void);
extern int ITB_SetMaxWorkers(int n);
extern int ITB_GetMaxWorkers(void);
extern int ITB_SetNonceBits(int n);
extern int ITB_GetNonceBits(void);
extern int ITB_SetBarrierFill(int n);
extern int ITB_GetBarrierFill(void);

extern int ITB_ParseChunkLen(void *header, size_t header_len, size_t *out_chunk_len);
extern int ITB_MaxKeyBits(void);
extern int ITB_Channels(void);
extern int ITB_HeaderSize(void);

extern int ITB_AttachLockSeed(uintptr_t noise_handle, uintptr_t lock_handle);

/* ---- Easy Mode encryptor (Phase 4) -------------------------------- */
extern int ITB_Easy_New(char *primitive, int key_bits, char *mac_name,
                        int mode, uintptr_t *out_handle);
extern int ITB_Easy_Free(uintptr_t handle);
extern int ITB_Easy_Encrypt(uintptr_t handle,
                            void *plaintext, size_t pt_len,
                            void *out, size_t out_cap, size_t *out_len);
extern int ITB_Easy_Decrypt(uintptr_t handle,
                            void *ciphertext, size_t ct_len,
                            void *out, size_t out_cap, size_t *out_len);
extern int ITB_Easy_EncryptAuth(uintptr_t handle,
                                void *plaintext, size_t pt_len,
                                void *out, size_t out_cap, size_t *out_len);
extern int ITB_Easy_DecryptAuth(uintptr_t handle,
                                void *ciphertext, size_t ct_len,
                                void *out, size_t out_cap, size_t *out_len);
extern int ITB_Easy_SetNonceBits(uintptr_t handle, int n);
extern int ITB_Easy_SetBarrierFill(uintptr_t handle, int n);
extern int ITB_Easy_SetBitSoup(uintptr_t handle, int mode);
extern int ITB_Easy_SetLockSoup(uintptr_t handle, int mode);
extern int ITB_Easy_SetLockSeed(uintptr_t handle, int mode);
extern int ITB_Easy_SetChunkSize(uintptr_t handle, int n);
extern int ITB_Easy_Primitive(uintptr_t handle, char *out, size_t cap_bytes, size_t *out_len);
extern int ITB_Easy_KeyBits(uintptr_t handle, int *out_status);
extern int ITB_Easy_Mode(uintptr_t handle, int *out_status);
extern int ITB_Easy_MACName(uintptr_t handle, char *out, size_t cap_bytes, size_t *out_len);
extern int ITB_Easy_SeedCount(uintptr_t handle, int *out_status);
extern int ITB_Easy_SeedComponents(uintptr_t handle, int slot,
                                   uint64_t *out, int cap_count, int *out_len);
extern int ITB_Easy_HasPRFKeys(uintptr_t handle, int *out_status);
extern int ITB_Easy_PRFKey(uintptr_t handle, int slot, uint8_t *out, size_t cap_bytes, size_t *out_len);
extern int ITB_Easy_MACKey(uintptr_t handle, uint8_t *out, size_t cap_bytes, size_t *out_len);
extern int ITB_Easy_Close(uintptr_t handle);
extern int ITB_Easy_Export(uintptr_t handle, void *out, size_t out_cap, size_t *out_len);
extern int ITB_Easy_Import(uintptr_t handle, void *blob, size_t blob_len);
extern int ITB_Easy_PeekConfig(void *blob, size_t blob_len,
                               char *prim_out, size_t prim_cap, size_t *prim_len,
                               int *key_bits_out, int *mode_out,
                               char *mac_out, size_t mac_cap, size_t *mac_len);
extern int ITB_Easy_LastMismatchField(char *out, size_t cap_bytes, size_t *out_len);
extern int ITB_Easy_NonceBits(uintptr_t handle, int *out_status);
extern int ITB_Easy_HeaderSize(uintptr_t handle, int *out_status);
extern int ITB_Easy_ParseChunkLen(uintptr_t handle, void *header, size_t header_len, size_t *out_chunk_len);

extern int ITB_Easy_NewMixed(char *prim_n, char *prim_d, char *prim_s, char *prim_l,
                             int key_bits, char *mac_name, uintptr_t *out_handle);
extern int ITB_Easy_NewMixed3(char *prim_n,
                              char *prim_d1, char *prim_d2, char *prim_d3,
                              char *prim_s1, char *prim_s2, char *prim_s3,
                              char *prim_l, int key_bits, char *mac_name,
                              uintptr_t *out_handle);
extern int ITB_Easy_PrimitiveAt(uintptr_t handle, int slot,
                                char *out, size_t cap_bytes, size_t *out_len);
extern int ITB_Easy_IsMixed(uintptr_t handle, int *out_status);

/* ---- Native Blob (Phase 4) ---------------------------------------- */
extern int ITB_Blob128_New(uintptr_t *out_handle);
extern int ITB_Blob256_New(uintptr_t *out_handle);
extern int ITB_Blob512_New(uintptr_t *out_handle);
extern int ITB_Blob_Free(uintptr_t handle);
extern int ITB_Blob_Width(uintptr_t handle, int *out_status);
extern int ITB_Blob_Mode(uintptr_t handle, int *out_status);
extern int ITB_Blob_SetKey(uintptr_t handle, int slot, void *key, size_t key_len);
extern int ITB_Blob_GetKey(uintptr_t handle, int slot, void *out, size_t out_cap, size_t *out_len);
extern int ITB_Blob_SetComponents(uintptr_t handle, int slot, uint64_t *comps, size_t count);
extern int ITB_Blob_GetComponents(uintptr_t handle, int slot, uint64_t *out, size_t out_cap, size_t *out_count);
extern int ITB_Blob_SetMACKey(uintptr_t handle, void *key, size_t key_len);
extern int ITB_Blob_GetMACKey(uintptr_t handle, void *out, size_t out_cap, size_t *out_len);
extern int ITB_Blob_SetMACName(uintptr_t handle, char *name, size_t name_len);
extern int ITB_Blob_GetMACName(uintptr_t handle, char *out, size_t out_cap, size_t *out_len);
extern int ITB_Blob_Export(uintptr_t handle, int opts_bitmask, void *out, size_t out_cap, size_t *out_len);
extern int ITB_Blob_Export3(uintptr_t handle, int opts_bitmask, void *out, size_t out_cap, size_t *out_len);
extern int ITB_Blob_Import(uintptr_t handle, void *blob, size_t blob_len);
extern int ITB_Blob_Import3(uintptr_t handle, void *blob, size_t blob_len);

/* ---- Streaming AEAD per-chunk ABI --------------------------------- */
/*
 * Per-chunk Streaming AEAD entry points. The caller drives the chunk
 * loop on the binding side: generate a 32-byte CSPRNG stream_id at
 * stream start, write it as wire prefix, track a running cumulative
 * pixel offset (sum of W * H over previously emitted chunks), and set
 * final_flag != 0 on the terminating chunk only. Each call computes
 * one chunk; same caller-allocated-buffer convention as the existing
 * ITB_EncryptAuth* family. The 128 / 256 / 512 entry points are kept
 * distinct purely for ABI symmetry; the underlying capi handler
 * dispatches by the seeds' native hash width.
 */
extern int ITB_EncryptStreamAuthenticated128(
    uintptr_t noise, uintptr_t data, uintptr_t start, uintptr_t mac,
    void *plaintext, size_t pt_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset, int final_flag,
    void *out, size_t out_cap, size_t *out_len);
extern int ITB_EncryptStreamAuthenticated256(
    uintptr_t noise, uintptr_t data, uintptr_t start, uintptr_t mac,
    void *plaintext, size_t pt_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset, int final_flag,
    void *out, size_t out_cap, size_t *out_len);
extern int ITB_EncryptStreamAuthenticated512(
    uintptr_t noise, uintptr_t data, uintptr_t start, uintptr_t mac,
    void *plaintext, size_t pt_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset, int final_flag,
    void *out, size_t out_cap, size_t *out_len);
extern int ITB_DecryptStreamAuthenticated128(
    uintptr_t noise, uintptr_t data, uintptr_t start, uintptr_t mac,
    void *ciphertext, size_t ct_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset,
    void *out, size_t out_cap, size_t *out_len, int *final_flag_out);
extern int ITB_DecryptStreamAuthenticated256(
    uintptr_t noise, uintptr_t data, uintptr_t start, uintptr_t mac,
    void *ciphertext, size_t ct_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset,
    void *out, size_t out_cap, size_t *out_len, int *final_flag_out);
extern int ITB_DecryptStreamAuthenticated512(
    uintptr_t noise, uintptr_t data, uintptr_t start, uintptr_t mac,
    void *ciphertext, size_t ct_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset,
    void *out, size_t out_cap, size_t *out_len, int *final_flag_out);
extern int ITB_EncryptStreamAuthenticated3x128(
    uintptr_t noise,
    uintptr_t data1, uintptr_t data2, uintptr_t data3,
    uintptr_t start1, uintptr_t start2, uintptr_t start3,
    uintptr_t mac,
    void *plaintext, size_t pt_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset, int final_flag,
    void *out, size_t out_cap, size_t *out_len);
extern int ITB_EncryptStreamAuthenticated3x256(
    uintptr_t noise,
    uintptr_t data1, uintptr_t data2, uintptr_t data3,
    uintptr_t start1, uintptr_t start2, uintptr_t start3,
    uintptr_t mac,
    void *plaintext, size_t pt_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset, int final_flag,
    void *out, size_t out_cap, size_t *out_len);
extern int ITB_EncryptStreamAuthenticated3x512(
    uintptr_t noise,
    uintptr_t data1, uintptr_t data2, uintptr_t data3,
    uintptr_t start1, uintptr_t start2, uintptr_t start3,
    uintptr_t mac,
    void *plaintext, size_t pt_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset, int final_flag,
    void *out, size_t out_cap, size_t *out_len);
extern int ITB_DecryptStreamAuthenticated3x128(
    uintptr_t noise,
    uintptr_t data1, uintptr_t data2, uintptr_t data3,
    uintptr_t start1, uintptr_t start2, uintptr_t start3,
    uintptr_t mac,
    void *ciphertext, size_t ct_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset,
    void *out, size_t out_cap, size_t *out_len, int *final_flag_out);
extern int ITB_DecryptStreamAuthenticated3x256(
    uintptr_t noise,
    uintptr_t data1, uintptr_t data2, uintptr_t data3,
    uintptr_t start1, uintptr_t start2, uintptr_t start3,
    uintptr_t mac,
    void *ciphertext, size_t ct_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset,
    void *out, size_t out_cap, size_t *out_len, int *final_flag_out);
extern int ITB_DecryptStreamAuthenticated3x512(
    uintptr_t noise,
    uintptr_t data1, uintptr_t data2, uintptr_t data3,
    uintptr_t start1, uintptr_t start2, uintptr_t start3,
    uintptr_t mac,
    void *ciphertext, size_t ct_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset,
    void *out, size_t out_cap, size_t *out_len, int *final_flag_out);
extern int ITB_Easy_EncryptStreamAuth(
    uintptr_t handle,
    void *plaintext, size_t pt_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset, int final_flag,
    void *out, size_t out_cap, size_t *out_len);
extern int ITB_Easy_DecryptStreamAuth(
    uintptr_t handle,
    void *ciphertext, size_t ct_len,
    uint8_t *stream_id, uint64_t cumulative_pixel_offset,
    void *out, size_t out_cap, size_t *out_len, int *final_flag_out);

/* ---- Format-deniability wrapper (Phase 7) ------------------------- */
/*
 * 12 raw libitb exports that back the public-facing itb_wrap* /
 * itb_unwrap* / itb_wrap_stream_writer_* / itb_unwrap_stream_reader_*
 * surface declared in itb.h. The cipherName argument is a UTF-8
 * NUL-terminated string ("aes" / "chacha" / "siphash"); see
 * `wrapper/wrapper.go` for the source-of-truth construction.
 */
extern int ITB_WrapperKeySize(char *cipher_name, size_t *out_size);
extern int ITB_WrapperNonceSize(char *cipher_name, size_t *out_size);
extern int ITB_Wrap(char *cipher_name,
                    void *key, size_t key_len,
                    void *blob, size_t blob_len,
                    void *out, size_t out_cap, size_t *out_len);
extern int ITB_Unwrap(char *cipher_name,
                      void *key, size_t key_len,
                      void *wire, size_t wire_len,
                      void *out, size_t out_cap, size_t *out_len);
extern int ITB_WrapInPlace(char *cipher_name,
                           void *key, size_t key_len,
                           void *blob, size_t blob_len,
                           void *out_nonce, size_t nonce_cap);
extern int ITB_UnwrapInPlace(char *cipher_name,
                             void *key, size_t key_len,
                             void *wire, size_t wire_len);
extern int ITB_WrapStreamWriter_Init(char *cipher_name,
                                     void *key, size_t key_len,
                                     void *out_nonce, size_t nonce_cap,
                                     uintptr_t *out_handle);
extern int ITB_WrapStreamWriter_Update(uintptr_t handle,
                                       void *src, size_t src_len,
                                       void *dst, size_t dst_cap);
extern int ITB_WrapStreamWriter_Free(uintptr_t handle);
extern int ITB_UnwrapStreamReader_Init(char *cipher_name,
                                       void *key, size_t key_len,
                                       void *wire_nonce, size_t nonce_len,
                                       uintptr_t *out_handle);
extern int ITB_UnwrapStreamReader_Update(uintptr_t handle,
                                         void *src, size_t src_len,
                                         void *dst, size_t dst_cap);
extern int ITB_UnwrapStreamReader_Free(uintptr_t handle);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ITB_FFI_H */
