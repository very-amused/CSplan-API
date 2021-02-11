# CSplan-API
CSplan - go backend

## Roadmap
- [x] CRUD Names
- [x] CRU Keys
- [x] CRUD Todos
- [x] Index management for todos
- [x] CRUD Tags
- [x] Limit crypto key size
- [x] CRUD no list todos
- [x] AES challenge based auth
- [x] Auth bypass CLI flag (with warning)
- [x] Add privacy settings (ip logging, reminders)
- [x] Add session management
- [x] Optimize storage efficiency of tokens
- [ ] Patch structs should use pointers so empty strings, etc aren't omitted
- [x] Add session identification to auth tokens
- [x] Refactor routes into subpackages, moving frequently reused code into a core package
- [x] Update both auth and crypto keys to store hash parameters
### Identity
- [ ] Support for both encrypted and unencrypted usernames, names, profile picture
- [ ] Unencrypted profile sharing perms
- [ ] User tag generation (id via username#tag) with unencrypted usernames
### Long term
- [ ] Anonymous account support (id via server assigned UserID, unable to reset password or receive info via mail)
