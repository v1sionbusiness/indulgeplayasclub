# IPC — MongoDB backup + restore drill

The Atlas free tier has no point-in-time recovery. Orders, payments and
member records ARE the business — this workflow dumps them weekly to
GitHub's artifact storage (private repo, 90-day artifact retention).

## One-time setup (owner action, ~5 minutes)

1. Create a **read-only** Atlas database user for backups:
   Atlas → Database Access → Add New Database User →
   "Read only" role, project-scoped. Name it e.g. `ipc-backup`.
   Never reuse the app's read/write URI for backups.
2. In this GitHub repo: Settings → Secrets and variables → Actions →
   New repository secret:
   - Name: `MONGODB_BACKUP_URI`
   - Value: `mongodb+srv://ipc-backup:<PASSWORD>@<cluster>.mongodb.net/ipc`
3. Done. The workflow runs every Sunday 16:00 Asia/Manila (08:00 UTC)
   and can also be run manually: Actions → Weekly MongoDB Backup → Run.

## What the workflow produces

- `mongodb-database-tools` runs `mongodump --uri=$MONGODB_BACKUP_URI`
- The dump is zipped to `ipc-mongo-<date>.zip`
- Stored as a GitHub Actions artifact (downloadable for 90 days)
- A stale-backup guard fails the run loudly if the dump comes up empty

## Restore drill (run quarterly — this is the part that saves the business)

1. Download the newest artifact zip and unzip it (a `dump/` folder).
2. Restore into a THROWAWAY local Atlas cluster or Docker mongo —
   never into the production database:

   ```bash
   mongorestore --uri="mongodb+srv://<user>:<pw>@<scratch-cluster>/ipc" dump/
   ```

3. Verify with counts (numbers must match the live dashboard):

   ```bash
   mongosh "<scratch-uri>/ipc" --eval '
     ["users","orders","payments","sessions","vouchers","products","collections"]
       .forEach(c => print(c, db.getCollection(c).countDocuments()))'
   ```

4. Sign in against the restored copy once and open one paid order.
5. Record the drill date here:

   | Date | Restored by | Verified | Notes |
   |------|-------------|----------|-------|
   |      |             |          |       |

## Honest limits

- GitHub artifacts expire after 90 days — archive a zip outside GitHub
  occasionally (club laptop / external drive).
- The backup user is read-only: a leaked backup URI can read the club
  database but can never write to it.
- Secrets live ONLY in GitHub Secrets or the Render environment — never
  in this repository, never in chat.
