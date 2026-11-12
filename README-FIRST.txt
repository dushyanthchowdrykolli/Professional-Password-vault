========================================================================
                       VAULT — QUICK START GUIDE
========================================================================

Thank you for downloading VAULT — the offline, dark-luxury password vault.

1. HOW TO RUN:
   - Double-click "VAULT.exe" inside this folder.
   - No Python or external packages are required.
   - Everything runs 100% locally on your machine with zero network calls.

2. WHERE YOUR DATA LIVES:
   - Your encrypted vault and logs are stored safely in your Windows user profile:
       %APPDATA%\VAULT\vault_database.vlt
   - Your data is NEVER stored inside this application folder.
   - Deleting, moving, or replacing this application folder will NEVER touch
     or delete your saved passwords.

3. HOW TO UPDATE:
   - When a new version of VAULT is released:
     a) Exit VAULT completely.
     b) Delete this entire application folder.
     c) Extract the new release ZIP in its place.
     d) Double-click the new VAULT.exe.
   - Your vault database will automatically load from %APPDATA%\VAULT\.
   - VAULT automatically creates a pre-update backup of your database on
     the first launch after an update.

4. FIRST-TIME LAUNCH NOTE (WINDOWS DEFENDER / SMARTSCREEN):
   - Because this application is distributed independently and is not signed
     with an expensive enterprise certificate, Windows SmartScreen may show:
     "Windows protected your PC — Unknown publisher".
   - Click "More info", then click "Run anyway".
   - You can verify the integrity of this package using the published SHA-256
     checksum in SHA256SUMS.txt.
========================================================================

