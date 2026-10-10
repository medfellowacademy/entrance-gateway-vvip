# Entrance Gateway

Special-queue pass system for the temple festival. The committee issues QR passes, guests show them on their phone, and the police scan them at the special gate and get a green ALLOW or red STOP screen.

It runs on **Vercel** (the app) with **Supabase** (the database).

| Page | Who uses it |
|---|---|
| `/admin` | Committee: issue passes, bulk upload, cancel, see gate entries, manage users |
| `/scan` | Gate devices: scan QR codes |
| `/p/<pass number>` | Guests: the pass itself, sent by WhatsApp link |

## Deploy

1. **Supabase**: open your project, click **Connect**, and copy the **Transaction pooler** connection string (port 6543). Put your database password in place of `[YOUR-PASSWORD]`.
2. **Vercel**: import this repository as a new project. Before the first deploy, add two environment variables:
   - `DATABASE_URL`: the connection string from step 1.
   - `ADMIN_PASSWORD`: the password for the first admin login (username `admin`).
3. Deploy, then open `/admin` and log in.

The app creates its own tables on first use, inside a separate `gateway` schema, so it does not touch other tables in the same Supabase project. That schema is not reachable through Supabase's public API keys.

Optional environment variables:

- `FESTIVAL_TZ`: time zone used to decide what "today" is (default `Asia/Kolkata`).
- `DATABASE_CA`: Supabase's CA certificate (Supabase dashboard, Database settings, SSL). When set, the app verifies the database server's identity.

`vercel.json` runs the app in Mumbai (`bom1`). If your Supabase project is in another region, change it to the Vercel region nearest to that one, so every scan stays fast.

## Try it on one computer

```bash
npm install
npm start
```

With no `DATABASE_URL` it uses a small built-in database in the `data/` folder and writes the admin login to `data/admin-login.txt`. Open `http://localhost:3000/admin`.

## Roles

- **Admin** has full control and no quota.
- **Issuer** is a committee member. They see only their own passes and cannot go over their quota (counted in persons).
- **Scanner** is a gate device login. It can only scan.

## Pass rules

- A pass covers 1 person or a family (up to 20 persons, all entering together).
- A pass is valid between its from and to dates and works **once per day**.
- A cancelled pass is refused at the gate as soon as the device syncs.

## At the gate

1. Open `/scan` on each device and log in with a Scanner user **while the device has internet**. It downloads the pass list and stays logged in for 30 days.
2. When online, every scan is checked with the server, so a pass used on one device is refused on the others. If two devices scan the same pass at the same moment, the database lets only one through.
3. When the network drops, the device keeps working by itself: it checks the QR signature and its own list, and uploads the entries when the network returns. A forwarded screenshot could get through on a second device only during an outage; such entries show up under **Gate entries** marked "Used twice".
4. Guests without a phone: type the pass number or mobile number in the box below the camera.

## Keep safe

- **The Supabase database is the whole system.** It holds the passes, the entries, and the key that signs every pass (table `gateway.secrets`). If that key is lost or replaced, all passes already sent stop working. Do not delete the project or the `gateway` schema during the festival.
- Supabase's free plan pauses a project after a week with no activity. Open the pass office in the days before the festival to make sure it is awake.
