Weird code salad
Theoretically I want the service to work like this:
Client and server already know each other's public keys
        ↓
Client sends auth packet + ephemeral public key
        ↓
Server verifies password/auth
        ↓
Server sends its ephemeral public key
        ↓
Both sides independently derive the same session key
        ↓
No session key is ever transmitted