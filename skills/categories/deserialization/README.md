# Insecure Deserialization Probes

**CWE-502** · 3 skill(s) · folder `categories/deserialization/`

## Skills in this shelf

- `web/Java deserialization object-graph probe` (CWE-502)
- `web/PHP unserialize offset probe` (CWE-502)
- `web/Python pickle invalid-load-key probe` (CWE-502)

## Technique

Engine-identifying error probes: Java ObjectInputStream (StreamCorruptededor invalid stream header on magic bytes), PHP unserialize (Error at offset), Python pickle (invalid load key). Each confirms attacker bytes reach the native deserializer before gadget hunting.

## Proof design (why it is falsifiable)

Driver-level exception strings on a deliberately malformed payload — framework errors cannot match them, and the benign control deserializes nothing.

## Bypass variants / escalation ("think more beats level")

- ysoserial gadget chains once engine + libs are known (CommonsCollections, etc.)
- PHP phar:// wrapper deserialization via file upload
- Pickle RCE via __reduce__ when pickle input is accepted
- .NET BinaryFormatter / JavaScript node-serialize siblings
- Content-type confusion to reach hidden deserializer paths

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — Insecure Deserialization (Java/PHP/Python)
- frohoff/ysoserial — gadget references

## False positives to rule out

Generic 500s — regexes pin deserializer-specific error vocabulary only.
