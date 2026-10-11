# Manual smoke tests

| Test | Input sample | Expected behavior |
|---|---|---|
| Bank alert | Built-in “Suspicious bank alert” | Flags urgency, verification/OTP terms and URL patterns |
| Job offer | Built-in “Suspicious job offer” | Flags registration fee and job-offer language |
| Benign reminder | Built-in “Possible legitimate message” | Few/no configured warning indicators |
| Shortened link | Built-in “Suspicious shortened link” | Flags URL shortener and urgency |
| Ordinary HTTPS URL | `https://example.com` | No obvious pattern warning; must not say “safe” |
| Telugu output | Any sample + select Telugu | Telugu risk label and safety advice display |
| Empty input | Clear input then analyze | Shows prompt to enter content |

These tests check that the demo behaves as expected; they do not establish model accuracy.
