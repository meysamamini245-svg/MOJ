# ViraX - starter social network

PHP + MySQL starter intended for shared hosting. Includes email/password registration, posts, likes, profiles, follows, user search, and a basic admin panel.

## Install on hosting
1. In cPanel create a MySQL database and database user; grant the user ALL PRIVILEGES on that database.
2. In phpMyAdmin select the database, choose Import, and import `schema.sql`.
3. Copy `config.example.php` to `config.php`. Put the exact database host/name/user/password in `config.php`.
4. Upload the project files to your domain's document root (often `public_html`). Upload `index.php`, `schema.sql`, `.htaccess`, `config.php`. Do not leave config.php publicly readable; the included .htaccess blocks direct access on Apache.
5. Open the site over HTTPS and register your personal account.
6. In phpMyAdmin open the SQL tab and run this query using your account email:
   `UPDATE users SET is_admin=1 WHERE email='YOUR-EMAIL@example.com';`
   Replace the email exactly. Then log out/in and use the مدیریت link.

## GitHub
Create a private repository. Upload the extracted project files. Do not upload `config.php`, database credentials, API keys, or real user data. Keep `config.example.php` as the template.

## Requirements and limitations
- PHP 8.1+ recommended, PDO MySQL, mbstring.
- This starter stores profile pictures as external image URLs; it does not upload image files.
- Email registration is not email-verified and there is no password-reset email flow yet. Add SMTP-based verification/password reset before public launch.
- Admin is enabled manually with SQL so ordinary signups cannot self-assign admin.
- Configure HTTPS in cPanel. Consider rate limiting, moderation/reporting, backups, and security review before opening the site to the public.
