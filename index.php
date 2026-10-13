<?php
declare(strict_types=1);
session_start();

$configPath = __DIR__ . '/config.php';
if (!file_exists($configPath)) {
    http_response_code(500);
    exit('Setup required: copy config.example.php to config.php and enter your database settings.');
}
$config = require $configPath;
try {
    $pdo = new PDO(
        'mysql:host='.$config['db_host'].';dbname='.$config['db_name'].';charset=utf8mb4',
        $config['db_user'], $config['db_pass'],
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]
    );
} catch (Throwable $e) {
    http_response_code(500);
    exit('Database connection failed. Check config.php and make sure schema.sql was imported.');
}
function e($v): string { return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function me(): ?array {
    global $pdo;
    if (empty($_SESSION['uid'])) return null;
    $q=$pdo->prepare('SELECT id,email,display_name,bio,avatar_url,is_admin,is_verified,is_banned FROM users WHERE id=?');
    $q->execute([$_SESSION['uid']]); $u=$q->fetch();
    if (!$u || $u['is_banned']) { unset($_SESSION['uid']); return null; }
    return $u;
}
function csrf(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function check_csrf(): void {
    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) { http_response_code(400); exit('Invalid request token. Refresh and try again.'); }
}
function go(string $url='index.php'): never { header('Location: '.$url); exit; }
$notice='';
if ($_SERVER['REQUEST_METHOD']==='POST') {
    check_csrf();
    $action=$_POST['action'] ?? '';
    try {
        if ($action==='register') {
            $email=strtolower(trim($_POST['email'] ?? ''));
            $name=trim($_POST['display_name'] ?? '');
            $pass=$_POST['password'] ?? '';
            if (!filter_var($email,FILTER_VALIDATE_EMAIL) || strlen($email)>190) throw new RuntimeException('Enter a valid email.');
            if (mb_strlen($name)<2 || mb_strlen($name)>80) throw new RuntimeException('Name must be 2–80 characters.');
            if (strlen($pass)<8) throw new RuntimeException('Password must be at least 8 characters.');
            $q=$pdo->prepare('INSERT INTO users(email,password_hash,display_name) VALUES(?,?,?)');
            $q->execute([$email,password_hash($pass,PASSWORD_DEFAULT),$name]);
            session_regenerate_id(true); $_SESSION['uid']=(int)$pdo->lastInsertId();
            go();
        } elseif ($action==='login') {
            $email=strtolower(trim($_POST['email'] ?? '')); $pass=$_POST['password'] ?? '';
            $q=$pdo->prepare('SELECT id,password_hash,is_banned FROM users WHERE email=?'); $q->execute([$email]); $u=$q->fetch();
            if (!$u || !password_verify($pass,$u['password_hash']) || $u['is_banned']) throw new RuntimeException('Email or password is incorrect, or the account is unavailable.');
            session_regenerate_id(true); $_SESSION['uid']=(int)$u['id']; go();
        } elseif ($action==='logout') {
            $_SESSION=[]; session_destroy(); go();
        } elseif ($action==='create_post') {
            $u=me(); if (!$u) throw new RuntimeException('Sign in first.');
            $body=trim($_POST['body'] ?? '');
            if ($body==='' || mb_strlen($body)>2000) throw new RuntimeException('Post must contain 1–2000 characters.');
            $pdo->prepare('INSERT INTO posts(user_id,body) VALUES(?,?)')->execute([$u['id'],$body]); go();
        } elseif ($action==='like') {
            $u=me(); if (!$u) throw new RuntimeException('Sign in first.');
            $pid=(int)($_POST['post_id'] ?? 0);
            $q=$pdo->prepare('SELECT 1 FROM likes WHERE user_id=? AND post_id=?'); $q->execute([$u['id'],$pid]);
            if ($q->fetch()) $pdo->prepare('DELETE FROM likes WHERE user_id=? AND post_id=?')->execute([$u['id'],$pid]);
            else $pdo->prepare('INSERT IGNORE INTO likes(user_id,post_id) VALUES(?,?)')->execute([$u['id'],$pid]);
            go($_SERVER['HTTP_REFERER'] ?? 'index.php');
        } elseif ($action==='follow') {
            $u=me(); if (!$u) throw new RuntimeException('Sign in first.');
            $target=(int)($_POST['target_id'] ?? 0);
            if ($target===(int)$u['id']) throw new RuntimeException('You cannot follow yourself.');
            $q=$pdo->prepare('SELECT 1 FROM follows WHERE follower_id=? AND following_id=?'); $q->execute([$u['id'],$target]);
            if ($q->fetch()) $pdo->prepare('DELETE FROM follows WHERE follower_id=? AND following_id=?')->execute([$u['id'],$target]);
            else $pdo->prepare('INSERT IGNORE INTO follows(follower_id,following_id) VALUES(?,?)')->execute([$u['id'],$target]);
            go('index.php?profile='.$target);
        } elseif ($action==='update_profile') {
            $u=me(); if (!$u) throw new RuntimeException('Sign in first.');
            $name=trim($_POST['display_name'] ?? ''); $bio=trim($_POST['bio'] ?? ''); $avatar=trim($_POST['avatar_url'] ?? '');
            if (mb_strlen($name)<2 || mb_strlen($name)>80 || mb_strlen($bio)>280 || mb_strlen($avatar)>500) throw new RuntimeException('Check profile field lengths.');
            if ($avatar!=='' && !filter_var($avatar,FILTER_VALIDATE_URL)) throw new RuntimeException('Avatar must be a valid image URL.');
            $pdo->prepare('UPDATE users SET display_name=?,bio=?,avatar_url=? WHERE id=?')->execute([$name,$bio,$avatar,$u['id']]); go('index.php?profile='.$u['id']);
        } elseif ($action==='admin_user') {
            $u=me(); if (!$u || !$u['is_admin']) throw new RuntimeException('Admin only.');
            $target=(int)($_POST['target_id'] ?? 0); $task=$_POST['task'] ?? '';
            if ($target===(int)$u['id']) throw new RuntimeException('You cannot change your own admin account.');
            if ($task==='verify') $pdo->prepare('UPDATE users SET is_verified=1-is_verified WHERE id=?')->execute([$target]);
            elseif ($task==='ban') $pdo->prepare('UPDATE users SET is_banned=1-is_banned WHERE id=?')->execute([$target]);
            go('index.php?admin=1');
        }
    } catch (PDOException $ex) {
        $notice = $ex->getCode()==='23000' ? 'That email is already registered.' : 'A database error occurred. Check your database setup.';
    } catch (Throwable $ex) { $notice=$ex->getMessage(); }
}
$user=me();
$profileId=isset($_GET['profile'])?(int)$_GET['profile']:0;
$search=trim($_GET['q'] ?? '');
$adminPage=isset($_GET['admin']) && $user && $user['is_admin'];
$profile=null;
if ($profileId) { $q=$pdo->prepare('SELECT id,display_name,bio,avatar_url,is_verified,created_at FROM users WHERE id=? AND is_banned=0'); $q->execute([$profileId]); $profile=$q->fetch(); }
?><!doctype html>
<html lang="fa" dir="rtl">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title><?=e($config['site_name'] ?? 'ViraX')?></title>
<style>
:root{--bg:#f3f5f9;--card:#fff;--ink:#172033;--muted:#697386;--line:#e3e7ef;--blue:#3767e8}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Tahoma,Arial,sans-serif;line-height:1.8}a{color:var(--blue);text-decoration:none}.top{background:#111a2d;color:#fff;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.brand{font-size:23px;font-weight:bold;letter-spacing:.5px}.wrap{max-width:760px;margin:20px auto;padding:0 12px}.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;margin-bottom:14px;box-shadow:0 3px 14px #17203308}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.muted{color:var(--muted);font-size:13px}.avatar{width:42px;height:42px;border-radius:50%;object-fit:cover;background:#dce5ff;display:inline-flex;align-items:center;justify-content:center;font-weight:bold;color:#234}.btn,button{border:0;border-radius:10px;padding:9px 13px;background:var(--blue);color:white;font:inherit;cursor:pointer}.btn2{background:#eaf0ff;color:#244bb4}input,textarea{width:100%;padding:11px;border:1px solid #d7dce7;border-radius:10px;font:inherit;margin:5px 0 10px;background:white}textarea{min-height:95px;resize:vertical}label{font-size:14px}.inline{display:inline-block;margin:0 3px}.inline button{padding:5px 10px;font-size:13px}.verified{color:#2875e8;font-weight:bold}.postbody{white-space:pre-wrap;overflow-wrap:anywhere}.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.grid .card{margin:0}@media(max-width:520px){.grid{grid-template-columns:1fr}.wrap{margin:12px auto}.top{padding:10px}}
</style></head><body>
<header class="top"><a class="brand" href="index.php" style="color:white">ViraX</a><div class="row">
<a href="index.php" style="color:white">خانه</a>
<form method="get" class="row" style="gap:4px"><input name="q" value="<?=e($search)?>" placeholder="جست‌وجوی کاربران" style="width:150px;margin:0;padding:6px"><button>جست‌وجو</button></form>
<?php if($user):?><a href="index.php?profile=<?=$user['id']?>" style="color:white">پروفایل</a><?php if($user['is_admin']):?><a href="index.php?admin=1" style="color:white">مدیریت</a><?php endif;?><form method="post" class="inline"><input type="hidden" name="csrf" value="<?=e(csrf())?>"><input type="hidden" name="action" value="logout"><button class="btn2">خروج</button></form><?php endif;?>
</div></header><main class="wrap">
<?php if($notice):?><div class="card" style="border-color:#e5a1a1"><?=e($notice)?></div><?php endif;?>
<?php if(!$user):?>
<div class="grid"><section class="card"><h2>ساخت حساب ویراکس</h2><form method="post"><input type="hidden" name="csrf" value="<?=e(csrf())?>"><input type="hidden" name="action" value="register"><label>نام نمایشی</label><input name="display_name" required minlength="2" maxlength="80"><label>ایمیل</label><input name="email" type="email" required><label>رمز عبور (حداقل ۸ حرف)</label><input name="password" type="password" required minlength="8"><button>ثبت‌نام</button></form></section>
<section class="card"><h2>ورود</h2><form method="post"><input type="hidden" name="csrf" value="<?=e(csrf())?>"><input type="hidden" name="action" value="login"><label>ایمیل</label><input name="email" type="email" required><label>رمز عبور</label><input name="password" type="password" required><button>ورود به حساب</button></form></section></div>
<div class="card"><b>به ویراکس خوش آمدی</b><p class="muted">برای ارسال پست، لایک و دنبال‌کردن کاربران ابتدا وارد حساب شو.</p></div>
<?php elseif($adminPage):?>
<section class="card"><h2>پنل مدیریت</h2><p class="muted">برای امنیت، حساب مدیر را با دستور SQL در راهنما فعال کن. اینجا می‌توانی تیک آبی بدهی یا حساب را مسدود/آزاد کنی.</p>
<?php $people=$pdo->query('SELECT id,email,display_name,is_admin,is_verified,is_banned FROM users ORDER BY created_at DESC LIMIT 200')->fetchAll(); foreach($people as $p):?><div class="row" style="justify-content:space-between;border-top:1px solid var(--line);padding:10px 0"><div><b><?=e($p['display_name'])?></b> <?= $p['is_verified']?'<span class="verified">✓</span>':''?><div class="muted"><?=e($p['email'])?> · <?= $p['is_banned']?'مسدود':''?></div></div><?php if(!$p['is_admin']):?><div class="row"><form method="post"><input type="hidden" name="csrf" value="<?=e(csrf())?>"><input type="hidden" name="action" value="admin_user"><input type="hidden" name="target_id" value="<?=$p['id']?>"><input type="hidden" name="task" value="verify"><button class="btn2">تیک آبی</button></form><form method="post"><input type="hidden" name="csrf" value="<?=e(csrf())?>"><input type="hidden" name="action" value="admin_user"><input type="hidden" name="target_id" value="<?=$p['id']?>"><input type="hidden" name="task" value="ban"><button><?= $p['is_banned']?'رفع مسدودی':'مسدود'?></button></form></div><?php endif;?></div><?php endforeach;?></section>
<?php elseif($profile):?>
<section class="card"><div class="row"><?php if($profile['avatar_url']):?><img class="avatar" src="<?=e($profile['avatar_url'])?>" alt="avatar"><?php else:?><span class="avatar"><?=e(mb_substr($profile['display_name'],0,1))?></span><?php endif;?><div><h2 style="margin:0"><?=e($profile['display_name'])?> <?= $profile['is_verified']?'<span class="verified">✓</span>':''?></h2><div class="muted">عضو از <?=e($profile['created_at'])?></div></div></div><p><?=e($profile['bio'])?></p>
<?php $q=$pdo->prepare('SELECT COUNT(*) FROM follows WHERE following_id=?');$q->execute([$profile['id']]);$followers=(int)$q->fetchColumn();$q=$pdo->prepare('SELECT COUNT(*) FROM follows WHERE follower_id=?');$q->execute([$profile['id']]);$following=(int)$q->fetchColumn();?><p class="muted"><?=$followers?> دنبال‌کننده · <?=$following?> دنبال‌شونده</p>
<?php if($user && (int)$user['id']===(int)$profile['id']):?><h3>ویرایش پروفایل</h3><form method="post"><input type="hidden" name="csrf" value="<?=e(csrf())?>"><input type="hidden" name="action" value="update_profile"><label>نام نمایشی</label><input name="display_name" required maxlength="80" value="<?=e($user['display_name'])?>"><label>درباره من (حداکثر ۲۸۰ حرف)</label><textarea name="bio" maxlength="280"><?=e($user['bio'])?></textarea><label>لینک عکس پروفایل (اختیاری)</label><input name="avatar_url" type="url" value="<?=e($user['avatar_url'])?>"><button>ذخیره تغییرات</button></form><?php elseif($user):?><form method="post"><input type="hidden" name="csrf" value="<?=e(csrf())?>"><input type="hidden" name="action" value="follow"><input type="hidden" name="target_id" value="<?=$profile['id']?>"><button class="btn2">دنبال‌کردن / لغو دنبال‌کردن</button></form><?php endif;?></section>
<?php elseif($search!==''):?>
<section class="card"><h2>نتایج جست‌وجو</h2><?php $q=$pdo->prepare('SELECT id,display_name,bio,is_verified FROM users WHERE is_banned=0 AND display_name LIKE ? ORDER BY display_name LIMIT 50');$q->execute(['%'.$search.'%']);$results=$q->fetchAll();if(!$results):?><p>کاربری پیدا نشد.</p><?php endif;foreach($results as $r):?><div class="row" style="padding:8px 0;border-bottom:1px solid var(--line)"><a href="index.php?profile=<?=$r['id']?>"><b><?=e($r['display_name'])?> <?= $r['is_verified']?'<span class="verified">✓</span>':''?></b></a><span class="muted"><?=e($r['bio'])?></span></div><?php endforeach;?></section>
<?php else:?>
<section class="card"><h2 style="margin-top:0">سلام <?=e($user['display_name'])?> 👋</h2><form method="post"><input type="hidden" name="csrf" value="<?=e(csrf())?>"><input type="hidden" name="action" value="create_post"><label>چی توی فکرت می‌گذره؟</label><textarea name="body" maxlength="2000" required placeholder="پستت رو بنویس..."></textarea><button>انتشار پست</button></form></section>
<?php $sql='SELECT p.id,p.user_id,p.body,p.created_at,u.display_name,u.is_verified,u.avatar_url,(SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) likes_count'.($user?',(SELECT COUNT(*) FROM likes l2 WHERE l2.post_id=p.id AND l2.user_id='.((int)$user['id']).') liked':''). ' FROM posts p JOIN users u ON u.id=p.user_id WHERE u.is_banned=0 ORDER BY p.created_at DESC LIMIT 100';$posts=$pdo->query($sql)->fetchAll();if(!$posts):?><div class="card">هنوز پستی نیست؛ اولین پست رو منتشر کن!</div><?php endif;foreach($posts as $p):?><article class="card"><div class="row"><a href="index.php?profile=<?=$p['user_id']?>"><b><?=e($p['display_name'])?> <?= $p['is_verified']?'<span class="verified">✓</span>':''?></b></a><span class="muted"><?=e($p['created_at'])?></span></div><p class="postbody"><?=e($p['body'])?></p><div class="row"><form method="post"><input type="hidden" name="csrf" value="<?=e(csrf())?>"><input type="hidden" name="action" value="like"><input type="hidden" name="post_id" value="<?=$p['id']?>"><button class="btn2"><?=isset($p['liked']) && $p['liked']?'♥ پسندیده':'♡ لایک'?> · <?=$p['likes_count']?></button></form><a href="index.php?profile=<?=$p['user_id']?>">مشاهده پروفایل</a></div></article><?php endforeach;?>
<?php endif;?>
<footer class="muted" style="text-align:center;padding:20px">ViraX · نسخه اولیه</footer></main></body></html>
