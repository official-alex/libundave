# My Research on Discord's "DAVE" Protocol

---

## TL;DR - Can This Actually Be Done?

After spending way too much time digging through Discord's open-source code and documentation, here's what I found:

**Yes, it's absolutely possible to decrypt DAVE-encrypted voice traffic.** Here's why:

1. When you join a call with valid credentials, you're a legit participant in the MLS group
2. Discord literally sends you the Welcome message with all the group secrets
3. From there, you can derive every sender's decryption key
4. The actual decryption is just standard AES-128-GCM

<details>
<summary>🤔 What is MLS?</summary>

**MLS (Messaging Layer Security)** is a protocol for end-to-end encrypted group communication, defined in RFC 9420. Think of it like Signal's protocol but designed specifically for groups. It lets everyone in a group agree on shared encryption keys without any server (including Discord) being able to see those keys.

The clever part is how it handles people joining and leaving - it uses a tree structure so you don't have to redo everything when someone joins.
</details>

<details>
<summary>🤔 What is AES-128-GCM?</summary>

**AES-128-GCM** is an encryption algorithm. Breaking it down:
- **AES** = Advanced Encryption Standard (the actual cipher)
- **128** = key size in bits (16 bytes)
- **GCM** = Galois/Counter Mode (a mode that provides both encryption AND authentication)

The "authentication" part is important - it means you can detect if someone tampered with the data. That's what the "auth tag" is for.
</details>

The catch? Nobody's publicly documented how to do this yet. I'd be the first to fully reverse engineer and implement it.

---

## What's In This Doc

1. [How The Whole Thing Works](#1-how-the-whole-thing-works)
2. [The MLS Key Exchange (The Hard Part)](#2-the-mls-key-exchange-the-hard-part)
3. [Voice Gateway Stuff](#3-voice-gateway-stuff)
4. [How Frames Get Encrypted/Decrypted](#4-how-frames-get-encrypteddecrypted)
5. [The Network Layer](#5-the-network-layer)
6. [System Architecture](#6-system-architecture)
7. [What I Found In libdave's Source Code](#7-what-i-found-in-libdaves-source-code)
8. [Libraries I'll Need](#8-libraries-ill-need)
9. [Code Examples](#9-code-examples)

---

## 1. How The Whole Thing Works

So Discord's DAVE system has two encryption layers. Here's a diagram I made:

```
╔══════════════════════════════════════════════════════════════╗
║                    DISCORD DAVE ARCHITECTURE                 ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║    ┌──────────┐       WebSocket        ┌──────────────┐      ║
║    │  Client  │◄──────────────────────►│Voice Gateway │      ║
║    │          │    MLS + Signaling     │   (wss://)   │      ║
║    └────┬─────┘                        └──────────────┘      ║
║         │                                                    ║
║         │         UDP/RTP (Encrypted Frames)                 ║
║         ▼                                                    ║
║    ┌──────────┐                        ┌──────────────┐      ║
║    │   SFU    │◄──────────────────────►│Other Clients │      ║
║    │ (Relay)  │                        │              │      ║
║    └──────────┘                        └──────────────┘      ║
║                                                              ║
║    TWO LAYERS OF ENCRYPTION:                                 ║
║    Layer 1: Transport (DTLS/SRTP) - between you and Discord  ║
║    Layer 2: E2EE (DAVE/MLS) - between you and other users    ║
║             ^^^ The SFU can't see inside this one            ║
║             (Discord literally cannot decrypt your calls)    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

<details>
<summary>🤔 What is an SFU?</summary>

**SFU (Selective Forwarding Unit)** is basically a smart relay server. Instead of everyone sending their audio to everyone else (which would be a nightmare with 10+ people), everyone sends to the SFU, and the SFU forwards it to everyone else.

The "selective" part means it can choose what to forward - like not sending video if someone's connection is bad, or prioritizing the person currently speaking.

With DAVE, the SFU can still do its job because it only needs the RTP headers (which aren't E2E encrypted), but it can't actually hear what anyone is saying.
</details>

<details>
<summary>🤔 What is SRTP/DTLS?</summary>

**SRTP (Secure Real-time Transport Protocol)** is encryption for media streams. It wraps RTP packets so they're encrypted between you and the server.

**DTLS (Datagram Transport Layer Security)** is basically TLS but for UDP. It's used to set up the SRTP keys.

These provide the "transport layer" encryption - protecting data between you and Discord's servers. DAVE adds another layer on top that Discord can't decrypt.
</details>

<details>
<summary>🤔 What is E2EE?</summary>

**E2EE (End-to-End Encryption)** means only the people in the conversation can decrypt the messages. The servers in between (Discord, in this case) can pass the encrypted data around but can't read it.

This is different from regular encryption where the server decrypts incoming data and re-encrypts it for the recipient.
</details>

The important thing here is that Layer 2 (the E2EE part) means Discord's servers literally cannot decrypt voice data. But since I'm a participant in the call, I get the keys. Thanks Discord!

### Protocol Specs (DAVE v1.1)

From what I dug up, here are the actual parameters they use:

| What                | Value                                      |
|---------------------|-------------------------------------------|
| MLS Version         | 1.0 (RFC 9420)                            |
| MLS Ciphersuite     | `DHKEMP256_AES128GCM_SHA256_P256` (ID: 2) |
| Media Cipher        | AES-128-GCM                               |
| Key Size            | 16 bytes                                  |
| Nonce               | 12 bytes (but only 4 bytes sent in frame) |
| Auth Tag            | 8 bytes (truncated from the usual 16)     |
| Magic Marker        | `0xFAFA`                                  |

<details>
<summary>🤔 What does that ciphersuite name mean?</summary>

`DHKEMP256_AES128GCM_SHA256_P256` breaks down to:
- **DHKEM** = Diffie-Hellman Key Encapsulation Mechanism (how keys are exchanged)
- **P256** = The elliptic curve used (also called secp256r1 or prime256v1)
- **AES128GCM** = The encryption algorithm for actual data
- **SHA256** = The hash function used for various operations

It's just a fancy way of saying "use these specific crypto algorithms together."
</details>

---

## 2. The MLS Key Exchange (The Hard Part)

This is where it gets complicated. MLS (Messaging Layer Security) is how everyone in the call agrees on encryption keys without Discord being able to see them. It's actually pretty cool cryptography - I'll give them that.

### How The Lifecycle Works

```
╔═══════════════════════════════════════════════════════════════════════╗
║                         MLS GROUP LIFECYCLE                           ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║   1. INIT                  2. KEY PACKAGE             3. PROPOSALS    ║
║   ┌─────────────┐         ┌─────────────┐          ┌─────────────┐    ║
║   │  Generate   │         │  Send Key   │          │  Voice GW   │    ║
║   │  Signature  │────────►│  Package    │─────────►│  Sends Add/ │    ║
║   │  Key Pair   │         │  to Server  │          │  Remove     │    ║
║   └─────────────┘         └─────────────┘          └──────┬──────┘    ║
║                                                           │           ║
║   4. COMMIT                5. WELCOME               6. DECRYPT        ║
║   ┌─────────────┐         ┌─────────────┐          ┌─────────────┐    ║
║   │  Someone    │         │  New member │          │  Now you    │    ║
║   │  commits    │◄────────│  gets the   │◄─────────│  can export │    ║
║   │  proposals  │         │  Welcome!   │          │  sender keys│    ║
║   └─────────────┘         └─────────────┘          └─────────────┘    ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
```

Basically: you generate keys → send a "key package" → Discord proposes adding you → someone commits → you get a Welcome message → now you're in the group and can derive everyone's keys. Pretty straightforward once you understand the flow.

<details>
<summary>🤔 What's a "Key Package"?</summary>

A **Key Package** is like your "membership application" to join an MLS group. It contains:
- Your public encryption key (so others can encrypt stuff for you)
- Your public signature key (so others can verify messages are from you)
- Your identity/credential (in Discord's case, your user ID)
- Some metadata like when it expires

You generate this before joining, send it to the server, and when someone wants to add you to the group, they use your key package to encrypt the welcome message that only you can decrypt.
</details>

<details>
<summary>🤔 What's a "Commit" and "Welcome"?</summary>

In MLS, changes to the group (adding/removing members) happen through **Proposals** and **Commits**:

- **Proposal**: "Hey, I think we should add user X" or "User Y left"
- **Commit**: "OK, I'm making these proposals official" - this actually changes the group state
- **Welcome**: A special message sent to new members containing everything they need to join (encrypted so only they can read it)

Only one person can commit at a time (the one who "wins" gets their commit accepted), which prevents weird race conditions.
</details>

### The Key Package

I found this in their `session.cpp` file - this is how they generate the key package:

```cpp
joinKeyPackage_ = std::make_unique<::mlspp::KeyPackage>(
    ciphersuite,
    joinInitPrivateKey_->public_key,
    *selfLeafNode_,
    LeafNodeExtensionsForProtocolVersion(protocolVersion_),
    *selfSigPrivateKey_
);
```

What's actually in there:
- Your HPKE public key (for encryption)
- Your signature public key (for auth)
- Your credential (just your Discord user ID as a 64-bit big-endian number)
- Lifetime set to basically forever (`not_before=0, not_after=2^64-1`) — because who needs key rotation anyway? /s

<details>
<summary>🤔 What is HPKE?</summary>

**HPKE (Hybrid Public Key Encryption)** is a standard (RFC 9180) for encrypting messages using public key cryptography.

The "hybrid" part means it combines:
1. Asymmetric crypto (like ECDH) to establish a shared secret
2. Symmetric crypto (like AES) to actually encrypt the data

This is more efficient than encrypting everything with public key crypto directly, which is slow for large data.
</details>

### How Sender Keys Get Derived (This Is The Good Stuff)

This is the critical part I found in their code. Each person in the call has their own encryption key, and here's how you derive it:

```cpp
// From session.cpp - GetKeyRatchet()
std::unique_ptr<KeyRatchet> Session::GetKeyRatchet(std::string const& userId) const noexcept
{
    // Turn the user ID string into a little-endian 64-bit number
    auto u64userId = strtoull(userId.c_str(), nullptr, 10);
    auto userIdBytes = ::mlspp::bytes_ns::bytes(sizeof(u64userId));
    memcpy(userIdBytes.data(), &u64userId, sizeof(u64userId));

    // Export the base secret from the MLS group
    // Label: "Discord Secure Frames v0"
    // Context: the user's ID (little-endian)
    // Length: 16 bytes
    auto baseSecret = currentState_->do_export(
        Session::USER_MEDIA_KEY_BASE_LABEL,  // "Discord Secure Frames v0"
        userIdBytes,
        kAesGcm128KeyBytes  // 16
    );

    return std::make_unique<MlsKeyRatchet>(
        currentState_->cipher_suite(),
        std::move(baseSecret)
    );
}
```

So the formula is basically:

```
base_secret = MLS-Exporter(
    label = "Discord Secure Frames v0",
    context = user_id_as_little_endian_64bit,
    length = 16
)

key_ratchet = HashRatchet(ciphersuite, base_secret)
actual_key = key_ratchet.get(generation)
```

The `generation` comes from the top byte of the nonce in each frame. More on that later.

<details>
<summary>🤔 What is a Key Ratchet / Hash Ratchet?</summary>

A **Key Ratchet** is a mechanism for generating a sequence of keys from a single "base secret." It's called a ratchet because it only goes forward - you can derive key #5 from the base, but you can't go backwards from key #5 to get key #4.

The **Hash Ratchet** specifically works by repeatedly hashing:
```
key_0 = HKDF(base_secret, "key_0")
key_1 = HKDF(base_secret, "key_1")
... and so on
```

This is useful because:
1. If someone steals key #5, they can't decrypt past messages (forward secrecy)
2. You can skip ahead to any key number without computing all the ones before it

Discord uses the "generation" number in each frame to tell you which key to use.
</details>

<details>
<summary>🤔 What does "little-endian" mean?</summary>

**Endianness** is about byte order when storing multi-byte numbers.

Take the number `0x12345678` (4 bytes):
- **Big-endian**: stored as `12 34 56 78` (most significant byte first)
- **Little-endian**: stored as `78 56 34 12` (least significant byte first)

Discord stores user IDs as little-endian 64-bit integers for the MLS context. Getting this wrong = wrong keys = decryption fails. Ask me how I know... 😅
</details>

---

## 3. Voice Gateway Stuff

### The Connection Flow

Here's what happens when you connect to voice, step by step:

```
You                              Voice Gateway                     SFU
 │                                     │                            │
 │──── Identify (op 0) ───────────────►│                            │
 │     max_dave_protocol_version: 1    │                            │
 │                                     │                            │
 │◄─── Ready (op 2) ───────────────────│                            │
 │     ssrc, ip, port, modes           │                            │
 │                                     │                            │
 │──── Select Protocol (op 1) ────────►│                            │
 │     protocol: "udp", mode: ...      │                            │
 │                                     │                            │
 │◄─── Session Desc (op 4) ────────────│                            │
 │     dave_protocol_version: 1        │                            │
 │     secret_key, mode                │                            │
 │                                     │                            │
 │◄─── External Sender (op 25) ────────│  (binary)                  │
 │     credential, signature_key       │                            │
 │                                     │                            │
 │──── Key Package (op 26) ───────────►│  (binary)                  │
 │     mls_key_package                 │                            │
 │                                     │                            │
 │◄─── Proposals (op 27) ──────────────│  (binary)                  │
 │     add_proposals                   │                            │
 │                                     │                            │
 │──── Commit+Welcome (op 28) ────────►│  (binary)                  │
 │     commit, welcome                 │                            │
 │                                     │                            │
 │◄─── Announce Commit (op 29) ────────│  (binary)                  │
 │◄─── Welcome (op 30) ────────────────│  (binary)                  │
 │     welcome_for_you                 │  (the keys are MINE now)   │
 │                                     │                            │
 │──── Ready for Transition (op 23) ──►│                            │
 │                                     │                            │
 │◄─── Execute Transition (op 22) ─────│                            │
 │                                     │                            │
 ├─────────────────────────────────────┼────────────────────────────┤
 │              UDP RTP MEDIA          │                            │
 │◄────────────────────────────────────┼───────────────────────────►│
```

<details>
<summary>🤔 What is SSRC?</summary>

**SSRC (Synchronization Source Identifier)** is a 32-bit number that identifies who's sending a particular audio/video stream in RTP.

Each participant in a call gets their own SSRC. When you receive an RTP packet, you check the SSRC to know who it came from. Discord tells you the SSRC-to-user mapping when people join/leave.

It's randomly generated to avoid collisions when multiple streams get mixed together.
</details>

<details>
<summary>🤔 What is a WebSocket?</summary>

**WebSocket** is a protocol for two-way communication over a single TCP connection. Unlike HTTP (request-response), WebSocket lets either side send messages at any time.

Discord uses WebSocket for:
- Main gateway (presence, messages, events)
- Voice gateway (voice state, MLS messages, signaling)

The actual audio/video goes over UDP (RTP), but all the control messages go over WebSocket.
</details>

### DAVE Opcodes

These are the special opcodes for E2EE stuff (21-31 are all binary format):

| Code | Name                               | Direction | What It Does                        |
|------|------------------------------------|-----------|-------------------------------------|
| 21   | `dave_protocol_prepare_transition` | S→C       | Heads up, transition coming         |
| 22   | `dave_protocol_execute_transition` | S→C       | OK do the transition now            |
| 23   | `dave_protocol_ready_for_transition`| C→S      | I'm ready for the transition        |
| 24   | `dave_protocol_prepare_epoch`      | S→C       | New epoch / group being recreated   |
| 25   | `dave_mls_external_sender`         | S→C       | Voice gateway's credentials         |
| 26   | `dave_mls_key_package`             | C→S       | Here's my key package               |
| 27   | `dave_mls_proposals`               | S→C       | Add/remove proposals                |
| 28   | `dave_mls_commit_welcome`          | C→S       | Committing with welcome attached    |
| 29   | `dave_mls_announce_commit`         | S→C       | Broadcasting the winning commit     |
| 30   | `dave_mls_welcome`                 | S→C       | Your welcome message                |
| 31   | `dave_mls_invalid_commit_welcome`  | C→S       | Something's wrong with the commit   |

### Binary Message Format

The binary messages look like this:

```
┌────────────────────────────────────────────┐
│         Opcode 26 - Key Package            │
├────────────────────────────────────────────┤
│ uint8   opcode = 26                        │
│ MLSMessage key_package_message             │
│   └── KeyPackage (RFC 9420 format)         │
└────────────────────────────────────────────┘

┌────────────────────────────────────────────┐
│       Opcode 25 - External Sender          │
├────────────────────────────────────────────┤
│ uint16  sequence_number                    │
│ uint8   opcode = 25                        │
│ SignaturePublicKey signature_key           │
│ Credential credential                      │
│   ├── uint16 credential_type = 1 (basic)   │
│   └── opaque identity<V>                   │
└────────────────────────────────────────────┘
```

---

## 4. How Frames Get Encrypted/Decrypted

### The Frame Format

Every encrypted audio/video frame looks like this:

```
╔═══════════════════════════════════════════════════════════════════════╗
║                      DAVE ENCRYPTED FRAME FORMAT                      ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║   0                   1                   2                   3       ║
║   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1     ║
║  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    ║
║  /                                                               /    ║
║  +           Interleaved media frame (variable size)             +    ║
║  /         (mix of unencrypted + encrypted chunks)               /    ║
║  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    ║
║  |                                                               |    ║
║  +              8-byte AES-GCM auth tag (truncated)              +    ║
║  |                                                               |    ║
║  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    ║
║  /             ULEB128 nonce (variable length)                   /    ║
║  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    ║
║  /         ULEB128 unencrypted range pairs (variable)            /    ║
║  +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    ║
║  /                               | Size Byte  |  Magic 0xFAFA   |     ║
║  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
```

The way you know something is a DAVE frame: it ends with `0xFAFA`. That's the magic marker. Very creative naming, Discord.

<details>
<summary>🤔 What is ULEB128?</summary>

**ULEB128 (Unsigned Little-Endian Base 128)** is a variable-length encoding for integers. Small numbers take fewer bytes, big numbers take more.

How it works:
- Each byte uses 7 bits for data and 1 bit (the high bit) to say "there's more"
- If high bit = 1, read another byte
- If high bit = 0, you're done

Examples:
- `0x05` (5) encodes as: `05` (1 byte)
- `0x80` (128) encodes as: `80 01` (2 bytes)
- `0x3FFF` (16383) encodes as: `FF 7F` (2 bytes)

It's used a lot in binary formats because most numbers are small, so you save space on average.
</details>

<details>
<summary>🤔 What is a Nonce?</summary>

A **nonce** (Number used ONCE) is a random or sequential value used exactly once with a given key. For AES-GCM:

- It MUST be unique for each message encrypted with the same key
- If you reuse a nonce with the same key, the encryption is completely broken
- AES-GCM uses a 12-byte (96-bit) nonce

Discord uses a counter as their nonce - it goes up by 1 for each frame. The "generation" in the top byte tells you which key to use, and the rest is the actual counter.
</details>

<details>
<summary>🤔 What's an "Auth Tag"?</summary>

The **Authentication Tag** (or just "tag") is how AES-GCM proves the data wasn't tampered with.

When encrypting, the algorithm produces:
1. The ciphertext (encrypted data)
2. A tag (typically 16 bytes)

When decrypting, you provide the tag. If the ciphertext or AAD was modified even slightly, the tag check fails and decryption is rejected.

Discord truncates this to 8 bytes to save bandwidth (voice/video generates a LOT of data). 8 bytes is still 64 bits of security, which is plenty for short-lived media frames.
</details>

### The Parsing Algorithm

I pulled this from `frame_processors.cpp` - here's how they parse incoming frames:

```cpp
void InboundFrameProcessor::ParseFrame(ArrayView<uint8_t> frame)
{
    Clear();

    constexpr auto MinSupplementalBytesSize =
        kAesGcm128TruncatedTagBytes + sizeof(SupplementalBytesSize) + sizeof(MagicMarker);
    
    // Step 1: Check if it's even big enough
    if (frame.size() < MinSupplementalBytesSize) return;

    // Step 2: Check for the magic marker at the end
    auto magicMarkerBuffer = frame.end() - sizeof(MagicMarker);
    if (memcmp(magicMarkerBuffer, &kMarkerBytes, sizeof(MagicMarker)) != 0) {
        return;  // Not a DAVE frame, skip it
    }

    // Step 3: Read the supplemental bytes size (1 byte before the marker)
    SupplementalBytesSize supplementalBytesSize;
    auto supplementalBytesSizeBuffer = magicMarkerBuffer - sizeof(SupplementalBytesSize);
    memcpy(&supplementalBytesSize, supplementalBytesSizeBuffer, sizeof(SupplementalBytesSize));

    // Step 4: Validate
    if (frame.size() < supplementalBytesSize) return;
    if (supplementalBytesSize < MinSupplementalBytesSize) return;

    auto supplementalBytesBuffer = frame.end() - supplementalBytesSize;

    // Step 5: Grab the 8-byte auth tag
    tag_ = MakeArrayView(supplementalBytesBuffer, kAesGcm128TruncatedTagBytes);

    // Step 6: Read the ULEB128 nonce
    auto nonceBuffer = supplementalBytesBuffer + kAesGcm128TruncatedTagBytes;
    auto readAt = nonceBuffer;
    truncatedNonce_ = static_cast<TruncatedSyncNonce>(ReadLeb128(readAt, end));

    // Step 7: Read the unencrypted ranges
    DeserializeUnencryptedRanges(readAt, unencryptedRangesSize, unencryptedRanges_);

    // Step 8: Split into authenticated data and ciphertext
    for (const auto& range : unencryptedRanges_) {
        auto encryptedBytes = range.offset - frameIndex;
        if (encryptedBytes > 0) {
            AddCiphertextBytes(frame.data() + frameIndex, encryptedBytes);
        }
        AddAuthenticatedBytes(frame.data() + range.offset, range.size);
        frameIndex = range.offset + range.size;
    }
    
    isEncrypted_ = true;
}
```

### The Actual Decryption (from openssl_cryptor.cpp)

Once you have all the pieces, decryption is straightforward AES-GCM:

```cpp
bool OpenSSLCryptor::Decrypt(
    ArrayView<uint8_t> plaintextBufferOut,
    ArrayView<const uint8_t> ciphertextBuffer,
    ArrayView<const uint8_t> tagBuffer,
    ArrayView<const uint8_t> nonceBuffer,
    ArrayView<const uint8_t> additionalData)
{
    // 1. Set the nonce
    EVP_DecryptInit_ex(cipherCtx_, nullptr, nullptr, nullptr, nonceBuffer.data());

    // 2. Set AAD (the unencrypted ranges become authenticated data)
    if (additionalData.size() > 0) {
        EVP_DecryptUpdate(cipherCtx_, nullptr, &plaintextOutSize,
            additionalData.data(), additionalData.size());
    }

    // 3. Decrypt the ciphertext
    EVP_DecryptUpdate(cipherCtx_, plaintextBufferOut.data(), &plaintextOutSize,
        ciphertextBuffer.data(), ciphertextBuffer.size());

    // 4. Set the expected tag (8 bytes truncated)
    EVP_CIPHER_CTX_ctrl(cipherCtx_, EVP_CTRL_GCM_SET_TAG,
        kAesGcm128TruncatedTagBytes, tagBufferCopy.data());

    // 5. Verify and finalize
    EVP_DecryptFinal_ex(cipherCtx_, plaintextBufferOut.data(), &plaintextOutSize);
    
    return true;
}
```

<details>
<summary>🤔 What is AAD (Additional Authenticated Data)?</summary>

**AAD (Additional Authenticated Data)** is data that gets authenticated (protected from tampering) but NOT encrypted.

In DAVE, some parts of the frame stay unencrypted (like certain codec headers) but we still want to detect if someone messed with them. So they go into the AAD.

When decrypting:
- If the AAD doesn't match what was used during encryption → auth tag fails → decryption rejected
- The AAD itself is never encrypted, just verified
</details>

### Nonce Expansion

The frame only has a 4-byte truncated nonce, but AES-GCM needs 12 bytes. Here's how they expand it:

```cpp
auto nonceBuffer = std::array<uint8_t, 12>();
memset(nonceBuffer.data(), 0, 12);  // First 8 bytes are zero
memcpy(nonceBuffer.data() + 8, &truncatedNonce, 4);  // Last 4 bytes are the nonce

// Result looks like: [00 00 00 00 00 00 00 00 N3 N2 N1 N0]
```

### How They Pick Which Key To Use

The "generation" determines which key from the ratchet to use. It's just the top byte of the nonce:

```cpp
auto generation = cryptorManager.ComputeWrappedGeneration(
    truncatedNonce >> 24  // Shift right by 24 bits = get the most significant byte
);
```

---

## 5. The Network Layer

### Connection Setup

Here's the basic flow in code form:

```javascript
// 1. Connect to voice WebSocket
const ws = new WebSocket(`wss://${endpoint}?v=8`);

// 2. Send Identify - THE KEY IS max_dave_protocol_version: 1
ws.send(JSON.stringify({
    op: 0,
    d: {
        server_id: guildId,
        user_id: userId,
        session_id: sessionId,
        token: voiceToken,
        video: false,
        max_dave_protocol_version: 1  // THIS enables DAVE (the magic flag)
    }
}));

// 3. Wait for Ready (op 2) with SSRC, IP, port

// 4. Do IP Discovery over UDP

// 5. Send Select Protocol
ws.send(JSON.stringify({
    op: 1,
    d: {
        protocol: "udp",
        data: {
            address: discoveredIP,
            port: discoveredPort,
            mode: "aead_aes256_gcm_rtpsize"
        },
        codecs: [
            { name: "opus", type: "audio", priority: 1000, payload_type: 120 }
        ]
    }
}));

// 6. Receive Session Description (op 4) with secret_key and dave_protocol_version
```

<details>
<summary>🤔 What is IP Discovery?</summary>

**IP Discovery** (sometimes called STUN-like discovery) is how you figure out your public IP and port when you're behind NAT.

Discord's version:
1. Send a special packet to their server with your SSRC
2. Server sees what IP:port it came from (your public address)
3. Server sends that info back to you
4. You tell Discord "hey, send my audio to this address"

This is necessary because your computer often doesn't know its own public IP (it just knows its local 192.168.x.x address).
</details>

### RTP Packet Structure

```
╔══════════════════════════════════════════════════════════════════╗
║                        RTP PACKET FORMAT                         ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  ┌──────────────────────────────────────────────────────────┐    ║
║  │             RTP HEADER (12 bytes, unencrypted)           │    ║
║  ├──────────────────────────────────────────────────────────┤    ║
║  │  Version + Flags │ Payload Type │   Sequence Number      │    ║
║  │     (1 byte)     │   (1 byte)   │     (2 bytes)          │    ║
║  ├──────────────────────────────────────────────────────────┤    ║
║  │                   Timestamp (4 bytes)                    │    ║
║  ├──────────────────────────────────────────────────────────┤    ║
║  │                      SSRC (4 bytes)                      │    ║
║  └──────────────────────────────────────────────────────────┘    ║
║                                                                  ║
║  ┌──────────────────────────────────────────────────────────┐    ║
║  │                    ENCRYPTED PAYLOAD                     │    ║
║  │   (Transport encrypted first, then DAVE E2EE inside)     │    ║
║  │   (it's like an encryption onion... shrek would approve) │    ║
║  └──────────────────────────────────────────────────────────┘    ║
║                                                                  ║
║  ┌──────────────────────────────────────────────────────────┐    ║
║  │              Transport Nonce (4 bytes)                   │    ║
║  └──────────────────────────────────────────────────────────┘    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

<details>
<summary>🤔 What is RTP?</summary>

**RTP (Real-time Transport Protocol)** is the standard for streaming audio/video over the internet. Pretty much every VoIP/video call uses it.

The header contains:
- **Sequence number**: detect packet loss and reorder
- **Timestamp**: sync audio/video timing
- **SSRC**: identify who's sending
- **Payload type**: what codec is being used

RTP itself doesn't provide encryption - that's what SRTP and DAVE add on top.
</details>

### The Two Decryption Layers

When you receive a packet, you gotta decrypt it twice:

```
         RECEIVE RTP PACKET
                │
                ▼
┌──────────────────────────────────────┐
│   LAYER 1: Transport Decryption      │
│   Mode: aead_aes256_gcm_rtpsize      │
│   Key: secret_key from Session Desc  │
│   This removes Discord's encryption  │
└──────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────┐
│      LAYER 2: DAVE Decryption        │
│   Check for magic marker 0xFAFA      │
│   Parse the supplemental data        │
│   Get sender key from MLS group      │
│   AES-128-GCM decrypt                │
└──────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────┐
│         LAYER 3: Codec               │
│   Opus decode for audio              │
│   H264/VP8/VP9/AV1 for video         │
└──────────────────────────────────────┘
                │
                ▼
        RAW PCM / RAW VIDEO
           (profit???)
```

<details>
<summary>🤔 What is Opus?</summary>

**Opus** is an audio codec designed for real-time communication. Discord uses it for all voice chat.

Why Opus is great:
- Low latency (important for real-time)
- Works well at many bitrates (6 kbps to 510 kbps)
- Handles both speech and music well
- Open standard, royalty-free

Discord typically uses 48kHz sample rate, stereo, at around 64-128 kbps.
</details>

---

## 6. System Architecture

### What I Need To Build

```
╔══════════════════════════════════════════════════════════════════════╗
║                     VOICE DECRYPTION ARCHITECTURE                    ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║   ┌──────────────────────────────────────────────────────────────┐   ║
║   │                      APPLICATION LAYER                       │   ║
║   │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  │   ║
║   │  │  Discord  │  │    MLS    │  │   DAVE    │  │   Audio   │  │   ║
║   │  │  Gateway  │  │  Session  │  │ Decryptor │  │  Handler  │  │   ║
║   │  │  Client   │  │  Manager  │  │           │  │           │  │   ║
║   │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  │   ║
║   └────────┼──────────────┼──────────────┼──────────────┼────────┘   ║
║            │              │              │              │            ║
║   ┌────────┼──────────────┼──────────────┼──────────────┼────────┐   ║
║   │        │         TRANSPORT LAYER     │              │        │   ║
║   │  ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐  │   ║
║   │  │   Voice   │  │    UDP    │  │ Transport │  │   Opus    │  │   ║
║   │  │  Gateway  │  │   Socket  │  │ Decryptor │  │  Decoder  │  │   ║
║   │  │ WebSocket │  │   (RTP)   │  │  (SRTP)   │  │           │  │   ║
║   │  └───────────┘  └───────────┘  └───────────┘  └───────────┘  │   ║
║   └─────────────────────────────────────────────────────────────-┘   ║
║                                                                      ║
║   ┌─────────────────────────────────────────────────────────────┐    ║
║   │                       CRYPTO LAYER                          │    ║
║   │  ┌───────────┐      ┌───────────┐      ┌───────────┐        │    ║
║   │  │  ts-mls   │      │  AES-GCM  │      │    Key    │        │    ║
║   │  │   (MLS)   │      │  (crypto) │      │  Ratchet  │        │    ║
║   │  └───────────┘      └───────────┘      └───────────┘        │    ║
║   └─────────────────────────────────────────────────────────────┘    ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

### Data Flow (How Audio Gets Processed)

```
╔═══════════════════════════════════════════════════════════════════╗
║                          INCOMING AUDIO FLOW                      ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║   UDP Socket                                                      ║
║       │                                                           ║
║       ▼                                                           ║
║   ┌────────────────┐                                              ║
║   │  RTP Packet    │                                              ║
║   │  (Encrypted)   │                                              ║
║   └───────┬────────┘                                              ║
║           │                                                       ║
║           ▼                                                       ║
║   ┌────────────────┐       ┌─────────────────────┐                ║
║   │   Transport    │──────►│  secret_key from    │                ║
║   │   Decrypt      │       │  Session Desc       │                ║
║   └───────┬────────┘       └─────────────────────┘                ║
║           │                                                       ║
║           ▼                                                       ║
║   ┌────────────────┐       ┌─────────────────────────────────┐    ║
║   │  DAVE Frame    │       │  Does it end with 0xFAFA?       │    ║
║   │  Detection     │──────►│  Yes → E2EE frame               │    ║
║   └───────┬────────┘       │  No → Passthrough/silence       │    ║
║           │                └─────────────────────────────────┘    ║
║           ▼                                                       ║
║   ┌────────────────┐       ┌─────────────────────────────────┐    ║
║   │  Parse Frame   │       │  Extract:                       │    ║
║   │  Supplemental  │──────►│   - 8-byte auth tag             │    ║
║   └───────┬────────┘       │   - ULEB128 nonce               │    ║
║           │                │   - Unencrypted ranges          │    ║
║           │                └─────────────────────────────────┘    ║
║           ▼                                                       ║
║   ┌────────────────┐       ┌─────────────────────────────────┐    ║
║   │  Get Sender    │       │  sender_key = MLS.export(       │    ║
║   │  Key from MLS  │──────►│    "Discord Secure Frames v0",  │    ║
║   └───────┬────────┘       │    little_endian(user_id),      │    ║
║           │                │    16                           │    ║
║           │                │  ).ratchet(generation)          │    ║
║           │                └─────────────────────────────────┘    ║
║           ▼                                                       ║
║   ┌────────────────┐       ┌─────────────────────────────────┐    ║
║   │  AES-128-GCM   │       │  plaintext = decrypt(           │    ║
║   │  Decrypt       │──────►│    key: sender_key,             │    ║
║   └───────┬────────┘       │    nonce: expand(trunc_nonce),  │    ║
║           │                │    aad: unencrypted_data,       │    ║
║           │                │    ciphertext: encrypted_data,  │    ║
║           │                │    tag: truncated_tag           │    ║
║           │                │  )                              │    ║
║           │                └─────────────────────────────────┘    ║
║           ▼                                                       ║
║   ┌────────────────┐                                              ║
║   │  Reconstruct   │       Put unencrypted + decrypted parts      ║
║   │  Original      │       back in their original positions       ║
║   └───────┬────────┘                                              ║
║           │                                                       ║
║           ▼                                                       ║
║   ┌────────────────┐                                              ║
║   │  Opus Decode   │       opus_decode(frame) → PCM samples       ║
║   └───────┬────────┘                                              ║
║           │                                                       ║
║           ▼                                                       ║
║   ┌────────────────┐                                              ║
║   │  Output/Save   │       WAV / PCM / whatever you want          ║
║   └────────────────┘                                              ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## 7. What I Found In libdave's Source Code

<details>
<summary>🤔 What is libdave?</summary>

**libdave** is Discord's official open-source implementation of the DAVE protocol. They published it on GitHub at `github.com/discord/libdave`.

It has:
- **C++ implementation**: The core library, uses OpenSSL and mlspp
- **JavaScript/WASM build**: Same C++ code compiled to WebAssembly for browser use
- **Protocol documentation**: Though not super detailed, it helped me figure things out

I spent a lot of time reading through the C++ source to understand exactly how encryption/decryption works.
</details>

### Constants (from common.h)

These are the magic numbers they use:

```cpp
// Sizes
constexpr size_t kAesGcm128KeyBytes = 16;
constexpr size_t kAesGcm128NonceBytes = 12;
constexpr size_t kAesGcm128TruncatedSyncNonceBytes = 4;
constexpr size_t kAesGcm128TruncatedSyncNonceOffset = 8;  // Where in the 12-byte nonce to put the 4 bytes
constexpr size_t kAesGcm128TruncatedTagBytes = 8;
constexpr size_t kRatchetGenerationBytes = 1;
constexpr size_t kRatchetGenerationShiftBits = 24;  // 8 * (4 - 1)

// Magic marker
constexpr MagicMarker kMarkerBytes = 0xFAFA;

// Timing stuff
constexpr auto kCryptorExpiry = std::chrono::seconds(10);

// Behavior
constexpr auto kMaxGenerationGap = 250;
constexpr auto kMaxMissingNonces = 1000;
constexpr auto kGenerationWrap = 256;  // 1 << 8

// Opus silence (sent when someone stops talking)
constexpr std::array<uint8_t, 3> kOpusSilencePacket = {0xF8, 0xFF, 0xFE};
```

### ULEB128 Encoding

They use ULEB128 for variable-length integers. Here's the read function:

```cpp
size_t ReadLeb128(const uint8_t*& readAt, const uint8_t* end) {
    size_t value = 0;
    size_t shift = 0;
    
    while (readAt < end) {
        uint8_t byte = *readAt++;
        value |= (byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) break;  // High bit not set = last byte
        shift += 7;
    }
    
    return value;
}
```

### Key Ratchet (from mls_key_ratchet.cpp)

```cpp
MlsKeyRatchet::MlsKeyRatchet(::mlspp::CipherSuite suite, bytes baseSecret) noexcept
    : hashRatchet_(suite, std::move(baseSecret))
{
}

EncryptionKey MlsKeyRatchet::GetKey(KeyGeneration generation) noexcept
{
    try {
        auto keyAndNonce = hashRatchet_.get(generation);
        return std::move(keyAndNonce.key.as_vec());
    }
    catch (const std::exception& e) {
        return {};
    }
}
```

---

## 8. Libraries I'll Need

### For a Node.js Implementation

```json
{
  "dependencies": {
    "ts-mls": "^1.0.0",           // MLS protocol implementation
    "@noble/curves": "^1.0.0",    // P-256 curve for the ciphersuite
    "ws": "^8.0.0",               // WebSocket client
    "@discordjs/opus": "^0.9.0",  // Opus codec (or opusscript for pure JS)
  }
}
```

Built-in Node stuff I'll use:
- `crypto` - for AES-GCM
- `dgram` - for UDP

### Alternative: Use Discord's WASM Build

Discord actually published their libdave as WebAssembly too:
- Located at `github.com/discord/libdave/js/wasm/`
- Compiled from C++ via `bindings_wasm.cpp`
- Would give native DAVE frame processing without reimplementing everything

---

## 9. Code Examples

### Voice Gateway Connection

```typescript
import WebSocket from 'ws';

class VoiceGateway {
    private ws: WebSocket;
    private ssrc: number;
    private secretKey: Uint8Array;
    private daveProtocolVersion: number;
    
    async connect(config: VoiceGatewayConfig): Promise<void> {
        this.ws = new WebSocket(`wss://${config.endpoint}?v=8`);
        
        this.ws.on('open', () => {
            // Identify with DAVE enabled
            this.send({
                op: 0,
                d: {
                    server_id: config.serverId,
                    user_id: config.userId,
                    session_id: config.sessionId,
                    token: config.token,
                    video: false,
                    max_dave_protocol_version: 1  // <-- This is the magic flag
                }
            });
        });
        
        this.ws.on('message', (data) => this.handleMessage(data));
    }
    
    private handleMessage(data: Buffer): void {
        // Binary messages (opcodes 21-31) are DAVE stuff
        if (data[0] >= 21 && data[0] <= 31) {
            this.handleBinaryMessage(data);
            return;
        }
        
        const msg = JSON.parse(data.toString());
        switch (msg.op) {
            case 2: this.handleReady(msg.d); break;
            case 4: this.handleSessionDescription(msg.d); break;
        }
    }
    
    private handleBinaryMessage(data: Buffer): void {
        const opcode = data[0];
        switch (opcode) {
            case 25: this.handleExternalSender(data); break;
            case 27: this.handleProposals(data); break;
            case 29: this.handleAnnounceCommit(data); break;
            case 30: this.handleWelcome(data); break; // The good stuff arrives here
        }
    }
}
```

### MLS Session Management

```typescript
import { 
    createGroup, generateKeyPackage, joinGroup, processMessage,
    getCiphersuiteImpl, getCiphersuiteFromName
} from 'ts-mls';

class DaveMlsSession {
    private mlsState: any;
    private senderKeyRatchets: Map<string, KeyRatchet> = new Map();
    
    async init(userId: string): Promise<Uint8Array> {
        // Get the right ciphersuite (P-256 + AES-128-GCM + SHA-256)
        const impl = await getCiphersuiteImpl(
            getCiphersuiteFromName("MLS_128_DHKEMP256_AES128GCM_SHA256_P256")
        );
        
        // Credential is just your user ID as bytes
        const credential = {
            credentialType: 1,  // basic
            identity: this.userIdToBytes(userId)
        };
        
        // Generate and return the key package
        const keyPkg = await generateKeyPackage({
            credential,
            cipherSuite: impl
        });
        
        return keyPkg.publicPackage;
    }
    
    async processWelcome(welcomeData: Uint8Array): Promise<void> {
        // Join the group using the welcome message
        this.mlsState = await joinGroup({
            context: this.context,
            welcome: welcomeData,
            keyPackage: this.keyPackage,
            privateKeys: this.privateKeys
        });
    }
    
    getSenderKey(senderUserId: string, generation: number): Uint8Array {
        const label = "Discord Secure Frames v0";
        const context = this.userIdToLittleEndian(senderUserId);
        
        const baseSecret = this.mlsState.export(label, context, 16);
        
        let ratchet = this.senderKeyRatchets.get(senderUserId);
        if (!ratchet) {
            ratchet = new KeyRatchet(baseSecret);
            this.senderKeyRatchets.set(senderUserId, ratchet);
        }
        
        return ratchet.getKey(generation);
    }
    
    private userIdToLittleEndian(userId: string): Uint8Array {
        const id = BigInt(userId);
        const buffer = new ArrayBuffer(8);
        const view = new DataView(buffer);
        view.setBigUint64(0, id, true);  // little-endian!
        return new Uint8Array(buffer);
    }
}
```

### DAVE Frame Decryption

```typescript
import { createDecipheriv } from 'crypto';

const MAGIC_MARKER = 0xFAFA;
const TAG_SIZE = 8;
const MARKER_SIZE = 2;
const SIZE_BYTE = 1;
const MIN_SUPPLEMENTAL = TAG_SIZE + SIZE_BYTE + MARKER_SIZE;  // 11 bytes

class DaveDecryptor {
    private mlsSession: DaveMlsSession;
    
    parseFrame(frame: Uint8Array): ParsedFrame | null {
        if (frame.length < MIN_SUPPLEMENTAL) return null;
        
        // Check magic marker at the end
        const markerOffset = frame.length - MARKER_SIZE;
        const marker = (frame[markerOffset] << 8) | frame[markerOffset + 1];
        if (marker !== MAGIC_MARKER) return null;
        
        // Read supplemental size
        const sizeOffset = markerOffset - SIZE_BYTE;
        const supplementalSize = frame[sizeOffset];
        
        if (frame.length < supplementalSize) return null;
        
        const supplementalStart = frame.length - supplementalSize;
        
        // Grab the 8-byte tag
        const tag = frame.slice(supplementalStart, supplementalStart + TAG_SIZE);
        
        // Read ULEB128 nonce
        let readPos = supplementalStart + TAG_SIZE;
        const { value: nonce, bytesRead } = this.readULEB128(frame, readPos);
        readPos += bytesRead;
        
        // Read unencrypted ranges
        const ranges: Array<{offset: number, size: number}> = [];
        while (readPos < sizeOffset) {
            const { value: offset, bytesRead: b1 } = this.readULEB128(frame, readPos);
            readPos += b1;
            const { value: size, bytesRead: b2 } = this.readULEB128(frame, readPos);
            readPos += b2;
            ranges.push({ offset, size });
        }
        
        // Split into authenticated and ciphertext
        const actualFrameSize = frame.length - supplementalSize;
        const authenticated: number[] = [];
        const ciphertext: number[] = [];
        let frameIdx = 0;
        
        for (const range of ranges) {
            if (range.offset > frameIdx) {
                for (let i = frameIdx; i < range.offset; i++) {
                    ciphertext.push(frame[i]);
                }
            }
            for (let i = range.offset; i < range.offset + range.size; i++) {
                authenticated.push(frame[i]);
            }
            frameIdx = range.offset + range.size;
        }
        
        if (frameIdx < actualFrameSize) {
            for (let i = frameIdx; i < actualFrameSize; i++) {
                ciphertext.push(frame[i]);
            }
        }
        
        return {
            tag, nonce,
            unencryptedRanges: ranges,
            authenticatedData: new Uint8Array(authenticated),
            ciphertext: new Uint8Array(ciphertext)
        };
    }
    
    decrypt(senderUserId: string, parsed: ParsedFrame): Uint8Array | null {
        // Generation is the top byte of the nonce
        const generation = parsed.nonce >>> 24;
        
        // Get the key
        const senderKey = this.mlsSession.getSenderKey(senderUserId, generation);
        if (!senderKey) return null;
        
        // Expand 4-byte nonce to 12 bytes
        const fullNonce = new Uint8Array(12);
        fullNonce[8] = (parsed.nonce >>> 24) & 0xFF;
        fullNonce[9] = (parsed.nonce >>> 16) & 0xFF;
        fullNonce[10] = (parsed.nonce >>> 8) & 0xFF;
        fullNonce[11] = parsed.nonce & 0xFF;
        
        try {
            const decipher = createDecipheriv('aes-128-gcm', senderKey, fullNonce);
            decipher.setAAD(parsed.authenticatedData);
            
            // Pad tag to 16 bytes
            const fullTag = new Uint8Array(16);
            fullTag.set(parsed.tag, 0);
            decipher.setAuthTag(fullTag);
            
            const plaintext = decipher.update(parsed.ciphertext);
            decipher.final();
            
            return new Uint8Array(plaintext);
        } catch (e) {
            return null;  // Decryption failed, probably wrong key
        }
    }
}
```

### Audio Handling

```typescript
import { OpusDecoder } from '@discordjs/opus';
import * as fs from 'fs';

class AudioHandler {
    private opusDecoder: OpusDecoder;
    private outputStream: fs.WriteStream;
    private sampleRate = 48000;
    private channels = 2;
    
    constructor(outputPath: string) {
        this.opusDecoder = new OpusDecoder(this.sampleRate, this.channels);
        this.outputStream = fs.createWriteStream(outputPath);
        this.writeWavHeader();
    }
    
    processFrame(opusFrame: Uint8Array): void {
        const pcm = this.opusDecoder.decode(Buffer.from(opusFrame));
        this.outputStream.write(pcm);
    }
    
    private writeWavHeader(): void {
        const header = Buffer.alloc(44);
        header.write('RIFF', 0);
        header.writeUInt32LE(0, 4);  // File size (fill in later)
        header.write('WAVE', 8);
        header.write('fmt ', 12);
        header.writeUInt32LE(16, 16);
        header.writeUInt16LE(1, 20);   // PCM
        header.writeUInt16LE(this.channels, 22);
        header.writeUInt32LE(this.sampleRate, 24);
        header.writeUInt32LE(this.sampleRate * this.channels * 2, 28);
        header.writeUInt16LE(this.channels * 2, 32);
        header.writeUInt16LE(16, 34);
        header.write('data', 36);
        header.writeUInt32LE(0, 40);  // Data size (fill in later)
        
        this.outputStream.write(header);
    }
    
    finalize(): void {
        const fileSize = this.outputStream.bytesWritten;
        const dataSize = fileSize - 44;
        
        const fd = fs.openSync(this.outputStream.path as string, 'r+');
        const buf = Buffer.alloc(4);
        
        buf.writeUInt32LE(fileSize - 8, 0);
        fs.writeSync(fd, buf, 0, 4, 4);
        
        buf.writeUInt32LE(dataSize, 0);
        fs.writeSync(fd, buf, 0, 4, 40);
        
        fs.closeSync(fd);
        this.outputStream.end();
    }
}
```

---

## Final Notes

Everything here came from:
- Discord's open-source `libdave` repo
- The `dave-protocol` whitepaper at daveprotocol.com  
- Reverse engineering the voice gateway messages
- Reading through the RFC 9420 (MLS) spec
- A lot of caffeine and questionable life choices

The main blocker right now is getting the MLS implementation right. The `ts-mls` library exists but isn't designed specifically for Discord's usage. I might need to do some adapting or just use Discord's WASM build directly. Will update the repo when I figure that part out.

But the key insight is: **as a legitimate participant in the call, I get the encryption keys**. I'm not trying to "break" the encryption - Discord literally hands me the keys because I'm supposed to be there. That's just how E2EE works lol.

---

*Last updated: when I finally understood what ULEB128 was 💀*
