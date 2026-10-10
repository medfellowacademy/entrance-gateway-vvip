# Entrance Gateway

Special-queue pass system for the temple festival. The committee issues QR passes, guests show them on their phone, and the police scan them at the special gate and get a green ALLOW or red STOP screen.

## Run

```bash
npm install
npm start
```

Needs Node.js 22.13 or newer. The server starts on port 3000 (set `PORT` to change it).

On first run it creates the `data/` folder and writes the admin login to `data/admin-login.txt`. Log in, set a new password under **Users**, then delete that file.

| Page | Who uses it |
|---|---|
| `/admin` | Committee: issue passes, bulk upload, cancel, see gate entries, manage users |
| `/scan` | Gate devices: scan QR codes |
| `/p/<pass number>` | Guests: the pass itself, sent by WhatsApp link |

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
2. When online, every scan is checked with the server, so a pass used on one device is refused on the others.
3. When the network drops, the device keeps working by itself: it checks the QR signature and its own list, and uploads the entries when the network returns. A forwarded screenshot could get through on a second device only during an outage; such entries show up under **Gate entries** marked "Used twice".
4. Guests without a phone: type the pass number or mobile number in the box below the camera.

## Hosting

- **Render**: `render.yaml` sets up the service with a persistent disk at `/var/data`. Create it as a Blueprint and enter `ADMIN_PASSWORD` when asked; that becomes the first admin password.
- The camera only works over **HTTPS**, so the server must be reached through an HTTPS address (any cloud host or reverse proxy provides this). `localhost` works for trying it out.
- Set `FESTIVAL_TZ` if the festival is not in Indian time (default `Asia/Kolkata`).
- **Back up the `data/` folder.** It holds the database and `keys.json`, the key that signs every pass. If `keys.json` is lost or replaced, all passes already sent stop working.
