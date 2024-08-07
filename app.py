from flask import (
    Flask,
    render_template,
    abort,
    request,
    Response,
    session,
    jsonify,
    Markup,
    send_from_directory,
    redirect,
    url_for,
    stream_with_context,
)
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from flask_dance.contrib.google import make_google_blueprint, google
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, text
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import SQLAlchemyError
from celery import Celery
from google.cloud import storage
from google.cloud.exceptions import NotFound
import requests
import uuid
import markdown as md
import pymysql
import math
import datetime
import re
import os
import json
import traceback
import time
import openai
import ffmpeg
import slackweb
import logging
import tempfile
from pprint import pprint
from functools import wraps
from dotenv import load_dotenv
from flask_caching import Cache

load_dotenv("/var/www/html/app/.env")
pymysql.install_as_MySQLdb()
app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app.secret_key = "your_secret_key"
app.config["MAX_CONTENT_LENGTH"] = 2000 * 1000 * 1000
app.config["JSON_AS_ASCII"] = False
app.config["STATIC_FOLDER"] = "static"
app.config["AUDIO_FOLDER"] = "audio"
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["CACHE_FOLDER"] = "cache"
app.config["OPENAI_KEY"] = os.environ.get("OPENAI_KEY")
app.config["CLIENT_ID"] = os.environ.get("CLIENT_ID")
app.config["CLIENT_SECRET"] = os.environ.get("CLIENT_SECRET")
app.config["SLACK_WEBHOOK_URI"] = os.environ.get("SLACK_WEBHOOK_URI")
app.config["REDIRECT_URL"] = os.environ.get("REDIRECT_URL")
app.config["CELERY_BROKER_URL"] = os.environ.get("CELERY_BROKER_URL")
app.config["CELERY_RESULT_BACKEND"] = os.environ.get("CELERY_BROKER_BACKEND")

# slack（デバッグ用）
slack = slackweb.Slack(url=app.config["SLACK_WEBHOOK_URI"])


def debug(message):
    slack.notify(text=message)


# SQLAlchemy初期化
db = SQLAlchemy(app)

# Google認証ブループリント作成
blueprint = make_google_blueprint(
    client_id=app.config["CLIENT_ID"],
    client_secret=app.config["CLIENT_SECRET"],
    redirect_url=app.config["REDIRECT_URL"],
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/drive.file",
        # "https://www.googleapis.com/auth/drive.readonly"
    ],
    offline=True,
    reprompt_consent=True,
)

app.register_blueprint(blueprint, url_prefix="/login")


# ユーザーテーブルのモデル定義
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(255), primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    pic = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(15))
    role = db.Column(db.String(15))
    password = db.Column(db.String(255))
    folder_id = db.Column(db.String(255))


# サマリーテーブルのモデル定義
class Summary(db.Model):
    __tablename__ = "summary"
    id = db.Column(db.String(255), primary_key=True)
    title = db.Column(db.String(50))
    transcript = db.Column(db.Text)
    summary = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))
    comment = db.Column(db.Text)
    date = db.Column(db.Date, default=func.curdate())
    status = db.Column(db.String(10))
    processed_percent = db.Column(db.Integer)
    userid = db.Column(db.String(255))
    is_shared = db.Column(db.Boolean)


# 共有テーブルのモデル定義
class Share(db.Model):
    __tablename__ = "share"
    shared_id = db.Column(db.String(255), primary_key=True)
    video_id = db.Column(db.String(255))
    guest_email = db.Column(db.String(255))
    owner_id = db.Column(db.String(255))
    gcs_file_path = db.Column(db.String(255))


# 404ページ
def page_not_found(error):
    return render_template("404.html"), 404


app.register_error_handler(404, page_not_found)

celery = Celery(app.name, broker=app.config["CELERY_BROKER_URL"])
celery.conf.update(app.config)


# ログイン必須処理デコレーション
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            user = get_userdata()
            if user:
                # ログイン状態じゃかなった場合
                if not google.authorized:
                    return render_template("loginform.html")

                # トークン期限切れチェック
                if (
                    google.token["expires_in"] < 1000
                    and "refresh_token" in google.token
                ):
                    google.refresh_token(
                        token_url="https://oauth2.googleapis.com/token",
                        refresh_token=google.token["refresh_token"],
                        client_id=app.config["CLIENT_ID"],
                        client_secret=app.config["CLIENT_SECRET"],
                    )

                    if "refresh_token" in google.token:
                        print(f'refresh_token: {google.token["refresh_token"]}')

            else:
                return render_template("loginform.html")

        except Exception as e:
            print(f"error => {e}")
            return render_template("loginform.html")

        return f(*args, **kwargs)

    return decorated_function


# 認証完了
@app.route("/google/authorized")
def authorized():
    # ログインユーザーデータ取得
    res = google.get("/oauth2/v2/userinfo")
    user_data = res.json()

    # セッション情報にユーザーデータ格納
    session["userdata"] = user_data

    # DB上のユーザーデータ検索
    user = get_userdata()

    # ユーザー情報無し（初回ログイン）
    if not user:
        # Googleドライブにフォルダ作成
        folder_data = create_google_drive_folder()
        if folder_data is None:
            return "フォルダ作成エラー", 500

        # DBにユーザーデータ格納
        user = User(
            id=user_data["id"],
            email=user_data["email"],
            name=user_data["name"],
            pic=user_data["picture"],
            type="google",
            role="standard",
            folder_id=folder_data["id"],
        )
        db.session.add(user)
        db.session.commit()

    # トップにリダイレクト
    return redirect(url_for("home"))


# Googleドライブのフォルダ作成関数
def create_google_drive_folder():
    # メタデータ
    folder_metadata = {
        "name": "メモリークラウド",
        "mimeType": "application/vnd.google-apps.folder",
    }
    res = google.post("/drive/v3/files", json=folder_metadata)

    # レスポンス異常
    if res.status_code != 200:
        return None

    folder_data = res.json()
    return folder_data


# ルート
@app.route("/")
@login_required
def index():
    # トップに遷移
    return redirect(url_for("home"))


# ログアウト
@app.route("/logout")
@login_required
def logout():
    try:
        # ユーザー情報取得
        user = get_userdata()

        if user:
            # 未ログインの場合
            if not google.authorized:
                return render_template("loginform.html")

            # セッションクリア
            token = google.token["access_token"]
            if token:
                resp = blueprint.session.post(
                    "https://accounts.google.com/o/oauth2/revoke",
                    params={"token": token},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if resp.ok:
                    blueprint.token = None
                    return redirect(url_for("index"))

        # 通常ログインの場合
        else:
            return render_template("loginform.html")

    # ユーザーIDがDBになかった場合
    except NoResultFound:
        return render_template("loginform.html")

    # ログアウト失敗
    return "ログアウトエラー"


# ユーザーリスト（メンテナンス用）
@app.route("/users", methods=["GET"])
@login_required
def users_list():
    # ユーザー情報取得
    user = get_userdata()

    if user:
        if user.role == "admin":
            res = db.session.query(
                User.name, User.id, User.email, User.type, User.role
            ).all()
        else:
            abort(404)
    else:
        return render_template("loginform.html")

    return render_template("users_list.html", objects=res)


# Redisの設定を環境変数から取得（Celeryと同じ設定を使用）
redis_url = os.environ.get("CELERY_BROKER_URL")

# キャッシュの設定
cache = Cache(app, config={"CACHE_TYPE": "RedisCache", "CACHE_REDIS_URL": redis_url})


# ファイルリスト
@app.route("/movies", methods=["GET"])
@login_required
@cache.memoize(timeout=100)  # 5分間キャッシュ
def movies():
    # ユーザー情報取得
    user = get_userdata()

    # ページネーションパラメータ
    page_size = 100  # 一度に取得するファイル数
    page_token = None
    all_files = []

    while True:
        # Googleドライブフォルダ情報取得
        drive = google.get(
            "/drive/v3/files",
            params={
                "q": f"(mimeType contains 'video/' or mimeType contains 'audio/') and '{user.folder_id}' in parents and trashed=false",
                "fields": "nextPageToken, files(id,name,mimeType,thumbnailLink)",
                "pageSize": page_size,
                "pageToken": page_token,
            },
        )
        drive_data = drive.json()

        all_files.extend(drive_data.get("files", []))
        page_token = drive_data.get("nextPageToken")
        if not page_token:
            break

    # SummaryDBのデータ取得（バッチで取得）
    file_ids = [f["id"] for f in all_files]
    db_data = (
        db.session.query(Summary.id, Summary.status, Summary.created_at, Summary.date)
        .filter(Summary.id.in_(file_ids))
        .all()
    )

    # DBデータをディクショナリに変換して高速なルックアップを可能にする
    db_data_dict = {record.id: record for record in db_data}

    # 返却用リスト
    result_list = []

    for f in all_files:
        # ステータス情報取得
        record = db_data_dict.get(f["id"])

        if record:
            # DBにレコードが存在した場合のみ追加
            f["status"] = record.status
            f["created_at"] = record.created_at
            f["date"] = record.date
            result_list.append(f)

    return render_template("movies.html", objects=result_list)


# 共有中リスト
@app.route("/sharing", methods=["GET"])
@login_required
def sharing():
    # ユーザー情報取得
    user = get_userdata()

    # 共有リストDB確認
    res = (
        db.session.query(Share.guest_email, Share.video_id, Summary.title)
        .join(Summary, Share.video_id == Summary.id)
        .filter(Share.owner_id == user.id)
    )

    return render_template("sharing.html", objects=res)


# 共有（され）リスト
@app.route("/shared", methods=["GET"])
@login_required
def shared():
    user = get_userdata()

    res = (
        db.session.query(
            Share.shared_id, Summary.created_at, Summary.date, User.name, Summary.title, Share.video_id
        )
        .join(Summary, Share.video_id == Summary.id)
        .join(User, Share.owner_id == User.id)
        .filter(Share.guest_email == user.email)
    )

    gcs_client = storage.Client()
    bucket = gcs_client.bucket("mc_shared")

    shared_data = []

    for share in res:
        thumbnail_blob = bucket.blob(f'thumbnails/{share.video_id}')
        thumbnail_url = thumbnail_blob.generate_signed_url(
            version="v4",
            expiration=datetime.timedelta(hours=1),
            method="GET"
        )
        thumbnail_url_escaped = Markup(json.dumps(thumbnail_url))
        print(thumbnail_url)

        shared_data.append({
            "created_at": share.created_at,
            "date": share.date,
            "name": share.name,
            "title": share.title,
            "thumbnailLink": thumbnail_url_escaped,
            "shared_id": share.shared_id
        })

    return render_template("shared.html", objects=shared_data)


# 再生画面（共有データ）
@app.route("/shared/<shared_id>", methods=["GET"])
@login_required
def video_shared(shared_id):
    # Googleログイン判定
    if not google.authorized:
        return redirect(url_for("google.login"))

    # ユーザーデータ取得
    user = get_userdata()

    # 共有データ
    if user:
        res = (
            db.session.query(Summary)
            .join(Share, Share.video_id == Summary.id)
            .filter(Share.guest_email == user.email, Share.shared_id == shared_id)
            .first()
        )
        # データない場合
        if not res:
            abort(404)

    # ログイン情報無し
    else:
        return render_template("loginform.html")

    res.transcript = Markup(res.transcript.replace("\n", "<br>"))
    res.summary = Markup(md.markdown(res.summary))
    res.comment_raw = res.comment
    res.comment = re.sub(
        "(https?://[\w!\?/\+\-_~=;\.,\*&@#\$%\(\)'\[\]]+)",
        '<a href="\\1">\\1</a>',
        res.comment,
    )
    res.comment = Markup(res.comment.replace("\n", "<br>"))

    return render_template("video_shared.html", data=res)


# 再生画面
@app.route("/video/<file_id>", methods=["GET", "POST"])
@login_required
def video(file_id):
    # Googleログイン判定
    if not google.authorized:
        return render_template("loginform.html")

    # ユーザーデータ取得
    user = get_userdata()

    # ユーザーの存在判定
    if user:
        # 管理者権限の時
        if user.role == "admin":
            res = Summary.query.filter_by(id=file_id).first()
        # 通常権限の時
        else:
            res = Summary.query.filter_by(id=file_id, userid=user.id).first()

        if not res:
            abort(404)
    else:
        return render_template("loginform.html")

    # POSTリクエスト（共有設定）
    if request.method == "POST":
        logger.debug("Received POST request to /share")
        data = request.get_json()
        logger.debug(f"Received data: {data}")
        emails_json = data.get("email")

        if not emails_json:
            return jsonify({"status": "error", "message": "Invalid request data"}), 400
        try:
            emails = json.loads(emails_json)

            gcs_client = storage.Client()
            bucket = gcs_client.bucket("mc_shared")
            blob = bucket.blob(f"shared_files/{file_id}")

            # Google Driveからファイル情報を取得
            file_info = google.get(
                f"/drive/v3/files/{file_id}?fields=id,name,thumbnailLink"
            ).json()
            thumbnail_url = file_info.get("thumbnailLink")

            new_shares = []
            existing_shares = []

            for email in emails:
                # 既存の共有をチェック
                existing_share = Share.query.filter_by(
                    video_id=file_id, guest_email=email["value"], owner_id=user.id
                ).first()

                if existing_share:
                    existing_shares.append(email["value"])
                else:
                    new_shares.append(email["value"])

            if new_shares:
                # 新しい共有がある場合　GCS存在チェックと圧縮処理
                if not blob.exists():
                    # Gドライブからダウンロード
                    file_content = google.get(
                        f"/drive/v3/files/{file_id}?alt=media"
                    ).content
                    logger.debug("GdriveOK")

                    # GCS格納（非同期）
                    task = compress_and_upload_to_gcs.delay(
                        file_content, file_id, "mc_shared", thumbnail_url
                    )
                    logger.debug(f"Task ID: {task.id}")

                # 新しい共有情報をDBに保存
                for email in new_shares:
                    share = Share(
                        shared_id=str(uuid.uuid4()),
                        video_id=file_id,
                        guest_email=email,
                        owner_id=user.id,
                        gcs_file_path=f"shared_files/{file_id}",
                    )
                    db.session.add(share)

                db.session.commit()

                return jsonify({"status": "success", "message": "共有完了"})
            else:
                return jsonify({"status": "warning", "message": "既に共有されています"})

        except Exception as e:
            db.session.rollback()
            return jsonify({"status": "error", "message": str(e)})

    res.transcript = Markup(res.transcript.replace("\n", "<br>"))
    res.summary = Markup(md.markdown(res.summary))
    res.comment_raw = res.comment
    res.comment = re.sub(
        "(https?://[\w!\?/\+\-_~=;\.,\*&@#\$%\(\)'\[\]]+)",
        '<a href="\\1">\\1</a>',
        res.comment,
    )
    res.comment = Markup(res.comment.replace("\n", "<br>"))

    return render_template("video.html", data=res)


@celery.task(bind=True)
def compress_and_upload_to_gcs(self, file_content, file_id, bucket_name, thumbnail_url):
    gcs_client = storage.Client()
    bucket = gcs_client.bucket(bucket_name)
    blob = bucket.blob(f"shared_files/{file_id}")

    temp_file_path = None
    compressed_file_path = None

    try:
        # 一時ファイル作成
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as temp_file:
            temp_file.write(file_content)
            temp_file_path = temp_file.name

        # 圧縮済み一時ファイルのパス
        compressed_file_path = f"{temp_file_path}_compressed.mp4"

        # 動画圧縮（ffmpeg）
        stream = ffmpeg.input(temp_file_path)
        stream = ffmpeg.filter(stream, "scale", width=1280, height=-1)
        stream = ffmpeg.output(
            stream,
            compressed_file_path,
            vcodec="libx264",
            acodec="aac",
            audio_bitrate="128k",
            preset="medium",
            crf=23,
        )
        ffmpeg.run(stream, overwrite_output=True, quiet=False)

        # 圧縮済みファイルをGCSに格納
        blob.upload_from_filename(compressed_file_path)
        logger.info(f"File {file_id} compressed and uploaded successfully.")

        # サムネイルの保存
        if thumbnail_url:
            thumbnail_blob = bucket.blob(f"thumbnails/{file_id}")
            thumbnail_content = requests.get(thumbnail_url).content
            thumbnail_blob.upload_from_string(
                thumbnail_content, content_type="image/jpeg"
            )

        return {
            "status": "success",
            "message": "File compressed and uploaded successfully.",
        }

    except ffmpeg.Error as e:
        logger.error(f"FFmpeg compression failed for {file_id}: {e.stderr.decode()}")
        blob.upload_from_string(file_content)
        return {
            "status": "warning",
            "message": "Compression failed, original file uploaded.",
        }

    except Exception as e:
        logger.error(f"Error processing file {file_id}: {str(e)}")
        return {"status": "error", "message": str(e)}

    finally:
        # 一時ファイル削除
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        if compressed_file_path and os.path.exists(compressed_file_path):
            os.remove(compressed_file_path)


# ストリーム
@app.route("/stream/<file_id>")
@login_required
def stream(file_id):
    # Googleログイン状態の確認
    if not google.authorized:
        return redirect(url_for("google.login"))

    range_header = request.headers.get("Range", None)
    byte1, byte2 = 0, None

    # 範囲リクエストの解析
    if range_header:
        match = re.search("bytes=(\d+)-(\d*)", range_header)
        groups = match.groups()

        if groups[0]:
            byte1 = int(groups[0])
        if groups[1]:
            byte2 = int(groups[1])

    # Google Drive APIから範囲のデータを取得
    headers = {"Range": f"bytes={byte1}-{byte2}" if byte2 else f"bytes={byte1}-"}
    res = google.get(
        f"/drive/v3/files/{file_id}?alt=media", stream=True, headers=headers
    )

    def generate():
        for chunk in res.iter_content(chunk_size=8192):
            yield chunk

    # 適切なヘッダーでレスポンスを作成
    length = res.headers.get("Content-Length")
    content_range = res.headers.get("Content-Range")
    status = 206 if range_header else 200

    video = Response(
        stream_with_context(generate()), content_type="video/mp4", status=status
    )
    video.headers["Accept-Ranges"] = "bytes"
    video.headers["Content-Length"] = length
    if content_range:
        video.headers["Content-Range"] = content_range

    return video


# ストリーム（共有）
@app.route("/stream/share/<file_id>")
@login_required
def stream_shared(file_id):
    user = get_userdata()
    if not user:
        return redirect(url_for("google.login"))

    # 共有情報を取得
    share = Share.query.filter_by(video_id=file_id, guest_email=user.email).first()
    if not share:
        abort(404)

    range_header = request.headers.get("Range", None)
    byte1, byte2 = 0, None

    # 範囲リクエストの解析
    if range_header:
        match = re.search("bytes=(\d+)-(\d*)", range_header)
        groups = match.groups()

        if groups[0]:
            byte1 = int(groups[0])
        if groups[1]:
            byte2 = int(groups[1])

    # GCSクライアントの初期化
    gcs_client = storage.Client()
    bucket = gcs_client.bucket("mc_shared")
    blob = bucket.blob(share.gcs_file_path)

    # ファイルの全体サイズを取得
    file_size = blob.size

    # file_sizeがNoneの場合、blobのメタデータを明示的に取得
    if file_size is None:
        blob.reload()
        file_size = blob.size

    # file_sizeがまだNoneの場合、エラーを発生させる
    if file_size is None:
        abort(500, description="Failed to get file size from GCS")

    # レンジの終了バイトを設定
    if byte2 is None or byte2 >= file_size:
        byte2 = file_size - 1

    # コンテンツの長さ
    content_length = byte2 - byte1 + 1

    # GCSからデータをストリーミング
    def generate():
        with blob.open("rb") as f:
            f.seek(byte1)
            remaining = content_length
            chunk_size = 8192

            while remaining > 0:
                chunk = f.read(min(chunk_size, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    # レスポンスヘッダーの設定
    headers = {
        "Content-Range": f"bytes {byte1}-{byte2}/{file_size}",
        "Accept-Ranges": "bytes",
        "Content-Length": str(content_length),
        "Content-Type": "video/mp4",
    }

    status = 206 if range_header else 200

    return Response(stream_with_context(generate()), status=status, headers=headers)


# ホーム
@app.route("/home", methods=["GET"])
@login_required
def home():
    return render_template("home.html")


# 非同期ダウンロード（GDrive => サーバ）
@celery.task
def drivetosvr(id, token):
    with app.app_context():
        try:
            headers = {"Authorization": f"Bearer {token}"}
            resp = requests.get(
                f"https://www.googleapis.com/drive/v3/files/{id}?alt=media",
                headers=headers,
            )

            if resp.status_code != 200:
                # ステータス書き込み「失敗」
                set_status(id, "failed", 0)
                return

            # Googleドライブ ⇒ サーバに保存
            filepath = os.path.join(app.root_path, app.config["UPLOAD_FOLDER"], id)
            with open(filepath, "wb") as f:
                for chunk in resp.iter_content(
                    chunk_size=32768
                ):  # chunk_sizeは適宜調整
                    if chunk:  # チャンクが空でないことを確認
                        f.write(chunk)

            # ステータス書き込み「アップロード完了」
            set_status(id, "uploaded", 0)
            main_process(filepath, id)
            os.remove(filepath)

        except Exception as e:
            # エラー情報をログに記録
            set_status(id, "failed", 0)
            raise e


# アップロード
@app.route("/ajax/upload", methods=["POST"])
def upload():
    # ファイルキーがそもそもなかった時エラー
    if "file" not in request.files:
        return jsonify(message="ファイルがありません"), 400
    # ファイルあった
    file = request.files["file"]
    # ファイル名が空だった時エラー
    if file.filename == "":
        return jsonify(message="ファイルが選択されていません"), 400
    user = get_userdata()
    result = to_drive(file, user.folder_id)

    if result == "404":
        # Googleドライブにフォルダ作成
        folder_data = create_google_drive_folder()
        if folder_data is None:
            return "フォルダ作成エラー", 500

        # DBにユーザーデータ格納
        user = User.query.filter_by(id=user.id).first()
        user.folder_id = folder_data["id"]

        db.session.commit()
        result = to_drive(file, user.folder_id)

    if result:
        itemcreate = Summary(
            id=result,
            title=os.path.splitext(file.filename)[0],
            status="uploading",
            processed_percent=0,
            userid=user.id,
            comment="なし",
            summary="loading",
            transcript="loading",
        )

        db.session.add(itemcreate)
        db.session.commit()

        token = google.token["access_token"]
        drivetosvr.delay(result, token)

        return jsonify(message="アップロード完了", file_id=result), 200
    else:
        return jsonify(message="アップロード失敗"), 500


def to_drive(file, folder_id):
    # Google APIクライアントを取得
    if not google.authorized:
        return None  # ユーザーがログインしていない場合

    # ファイルのメタデータを設定
    file_metadata = {"name": os.path.splitext(file.filename)[0], "parents": [folder_id]}

    # ファイルをGoogle Driveにアップロード
    result = google.post(
        "/upload/drive/v3/files?uploadType=multipart",
        files={
            "data": (
                "metadata",
                json.dumps(file_metadata),
                "application/json; charset=UTF-8",
            ),
            "file": (
                os.path.splitext(file.filename)[0],
                file.stream,
                "application/octet-stream",
            ),
        },
    )

    if result.status_code == 200:
        file_id = result.json().get("id")
        return file_id

    return None


def main_process(filepath, id):
    data = {}
    text = ""
    text_withtime = ""
    summary = ""

    try:
        # 動画分割時間
        split_time = 60 * 40

        # OpenAI APIキー
        openai.api_key = app.config["OPENAI_KEY"]

        # 尺チェック
        duration = get_duration(filepath)

        # 尺が指定時間以下
        if duration <= split_time:
            # 音声ファイル
            output_file = os.path.join(
                app.root_path, app.config["AUDIO_FOLDER"], f"{id}_audio.mp3"
            )

            set_status(id, "Encode", 10)
            encode(filepath, output_file)

            set_status(id, "Transcript", 40)
            transcript = whisper(output_file)
            text = formattext(transcript.segments)

            set_status(id, "Timecode", 60)
            text_withtime += timecode(transcript.segments, 0)["text"]

            set_status(id, "Summarize", 80)
            os.remove(output_file)

        # 尺が指定時間超え
        else:
            # 分割処理
            total_steps = math.ceil(duration / split_time) * 3
            offset = 0.00

            for t in range(0, int(duration), split_time):
                current_basestep = ((1 + t / split_time) - 1) * 3

                # 進捗率：30% + α
                set_status(id, "Encode", (current_basestep + 1) / total_steps * 80)

                # 音声ファイル
                output_file = os.path.join(
                    app.root_path, app.config["AUDIO_FOLDER"], f"{id}_audio_{t}.mp3"
                )

                # エンコード
                encode(filepath, output_file, t, split_time)

                # 進捗率：40% + α
                set_status(id, "Transcript", (current_basestep + 2) / total_steps * 80)

                # 文字起こし
                transcript = whisper(output_file)

                # 生テキスト
                text += formattext(transcript.segments)
                if text == "error":
                    raise Exception("whisper: error")

                # 進捗率：60% + α
                set_status(id, "Timecode", (current_basestep + 3) / total_steps * 80)

                # タイムコード
                tc = timecode(transcript.segments, offset)
                text_withtime += tc["text"]

                # 分割によるタイムコードズレ補正
                offset += tc["end"]

                os.remove(output_file)

        start = 0
        max_len = 5000
        total_steps = math.ceil(len(text) / max_len)

        while start < len(text):
            current_basestep = (1 + start / max_len) - 1
            set_status(
                id, "Summarize", 80 + ((current_basestep + 1) / total_steps * 20) - 1
            )
            end = start + max_len

            # 部分文字列を取得
            substr = text[start:end]

            # 最後の改行までを切り詰める
            cut_string = cut_at_last_newline(substr, max_len)

            # 要約結果
            summary += gpt(cut_string)

            # 次の開始位置を設定
            start = end

        # 進捗率：100%
        set_status(id, "Complete", 100)

        data["transcript"] = Markup(text_withtime.replace("\n", "<br>"))
        data["summary"] = Markup(md.markdown(summary))

        summary_record = db.session.query(Summary).filter(Summary.id == id).first()

        if summary_record:
            # フィールドを更新
            summary_record.summary = summary
            summary_record.transcript = text_withtime

            # 変更をコミット
            db.session.commit()

    except Exception as e:
        set_status(id, "failed", 0)
        data["message"] = traceback.format_exc()
        print(traceback.format_exc())
        # db.session.query(Summary).filter(Summary.id == id).delete()
        # db.session.commit()

    return data


# 最後の改行までの文字列を返す関数
def cut_at_last_newline(s, max_length):
    last_newline_pos = s.rfind("\n")
    return s[:last_newline_pos] if last_newline_pos != -1 else s


# メディア情報取得
def get_duration(filepath):
    probe = ffmpeg.probe(filepath)
    info = next(s for s in probe["streams"])
    print(info)

    # 尺
    return float(info["duration"])


# エンコード処理
def encode(input, output, startpos=None, duration=None):
    print("Encode: Start")
    if startpos is None and duration is None:
        stream = ffmpeg.input(input)
    else:
        stream = ffmpeg.input(input, ss=startpos, t=duration)

    audio = stream.audio
    out = ffmpeg.output(audio, output, ar=24000, bitrate="256k", acodec="mp3")
    ffmpeg.run(out, overwrite_output=True, quiet=False)


# 文字起こし処理（Whisper）
def whisper(input):
    print("Whisper: Start")
    audio_file = open(input, "rb")

    for _ in range(10):
        try:
            transcript = openai.Audio.transcribe(
                "whisper-1",
                audio_file,
                language="ja",
                temperature=0,
                response_format="verbose_json",
            )

        except Exception as e:
            print(e)
            print("Whisper: Retry")
            time.sleep(5)

        else:
            print(f"Whisper: Success")
            return transcript
    return "error"


# ステータス情報格納
def set_status(id, status, percent):
    try:
        summary = db.session.query(Summary).filter_by(id=id).first()
        if summary:
            # レコードの値を更新
            summary.status = status
            summary.processed_percent = percent

            # 変更をデータベースにコミット
            db.session.commit()
            print(f"Status update succeeded: [id]{id}, [stat]{status}")
        else:
            print("No record")
    except SQLAlchemyError as e:
        print("error", str(e))
        db.session.rollback()


# 要約処理
def gpt(message):
    # プロンプト（GPT）
    template = """
    ## 命令
        あなたは日本語を流暢に書くことができる、極めて優秀なライターです。
        今から、ある打ち合わせの音声を、文字に書き起こしたものを入力します。
        あなたは、与えられた書き起こしに基づき、打ち合わせ内容を網羅した完璧な要約を出力します。
        誤字・脱字があるため、話の内容を予測して置き換えてください。
        要約する際には、以下の「制約条件」の項目に記載された条件を厳守すること。
        出力の見本を「出力例」の項目に書いているので、必ず参考にすること。

    ## 制約条件
        - 入力テキスト内で述べられている事柄は、必ず全て網羅すること。
        - 出力するテキストの末尾には、必ず一つだけ改行を入れること。
        - 自分のやっていることを絶対に説明しないこと。出力するのは絶対に要約のみとすること。
        - 箇条書き形式の要約のみを出力し、絶対に他の事は書かないこと。
        - 必ずmarkdown形式で出力をし、読みやすい箇条書きにする必要があります。
        - 適切な改行、インデントを入れ、読みやすくすること。
        - 状況説明は絶対にしないこと。
        - 出力するテキストが、要約である旨の記載は必要ありません。絶対に書かないこと。
        - 要約がない場合は「---」とだけ出力し、それについて言及しないこと。
        - 出力はそれぞれ短い文章で説明された箇条書き形式とし、言語は日本語のみを使用すること。
        - 主語、述語がいずれも欠けないように説明をする必要があります。
        - 何も書かれていない行は出力しないこと。
        - 自己紹介はしないこと。
        - 自分のやっているタスクは絶対に説明しないこと。
        - 重要なキーワードを必ず含めること。
        - 数字や日付といった情報は、特に重要であると意識すること。
        - 文章の意味を変更することは絶対にしないこと。
        - 架空の表現や、存在しない単語は使用しないこと。
        - 重複する内容を複数回書かないこと。
        - 出力は、必ずmarkdown形式のみで出力すること。
        - 出力は全てmarkdown形式のみを使用し、plaintextは絶対に含めないこと。
        - 前置きや後書き、文章での説明は不要。箇条書きされた要約のみを出力すること。

    ## 出力例
        - 大項目
            - 中項目
            - 中項目
                
        - 大項目
            1. 中項目
            2. 中項目
            3. 中項目
    
    ## 入力
    """
    print("GPT: Start")
    for _ in range(30):
        try:
            completion = openai.ChatCompletion.create(
                model="gpt-4-1106-preview",
                temperature=0.02,
                messages=[
                    {"role": "system", "content": template},
                    {"role": "user", "content": message + "\n\n## 出力\n"},
                ],
            )

        except Exception as e:
            print(e)
            print("GPT: Retry")
            time.sleep(5)

        else:
            print(f"GPT: Success, UsageTokens: {completion.usage}")
            return completion.choices[0].message.content + "\n"


# タイムコード付加
def timecode(segments, offset):
    res = ""
    for segment in segments:
        start_m, start_s = divmod(int(offset + segment.start), 60)
        start_h, start_m = divmod(start_m, 60)
        start = f"{start_h:02d}:{start_m:02d}:{start_s:02d}"

        end_m, end_s = divmod(int(offset + segment.end), 60)
        end_h, end_m = divmod(end_m, 60)
        end = f"{end_h:02d}:{end_m:02d}:{end_s:02d}"

        res += f'[{start} - {end}]: {segment.text.encode().decode("utf-8")}\n'
    return dict(text=res, end=segment.end)


# 文字列整形
def formattext(segments):
    res = ""
    for segment in segments:
        res += f'{segment.text.encode().decode("utf-8")}\n'
    return res


# ajax：議事録削除
@app.route("/ajax/delete", methods=["POST"])
def delete():
    data = request.get_json()
    file_id = data.get("id")

    # ユーザー情報取得
    user = get_userdata()

    if not file_id:
        return (
            jsonify({"status": "error", "message": "file_id not found"}),
            400,
        )

    try:
        # DBから該当するレコードを削除
        record = Summary.query.filter_by(id=file_id, userid=user.id).first()
        if record:
            # GoogleドライブAPIを使ってファイルを削除
            response = google.delete(f"/drive/v3/files/{file_id}")
            if response.status_code == 204:
                db.session.delete(record)
                db.session.commit()
                share_record = Share.query.filter_by(
                    video_id=file_id, owner_id=user.id
                ).first()
                if share_record:
                    db.session.delete(share_record)
                    db.session.commit()
                return {"status": "success", "message": "delete success."}
            else:
                return jsonify({"status": "error", "message": "delete error."}), 404
        else:
            return jsonify({"status": "error", "message": "record not found."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ajax：共有解除
@app.route("/ajax/deleteshare", methods=["POST"])
def deleteshare():
    data = request.get_json()
    file_id = data.get("id")
    guest = data.get("guest")

    user = get_userdata()

    if not user:
        return (
            jsonify({"status": "error", "message": "ユーザー認証に失敗しました"}),
            401,
        )

    if not file_id or not guest:
        return (
            jsonify({"status": "error", "message": "必要な情報が不足しています"}),
            400,
        )

    try:
        # DBから該当するレコードを取得
        share_record = Share.query.filter_by(
            video_id=file_id, owner_id=user.id, guest_email=guest
        ).first()

        if not share_record:
            return (
                jsonify({"status": "error", "message": "共有レコードが見つかりません"}),
                404,
            )

        # DBからレコードを削除
        db.session.delete(share_record)
        db.session.commit()

        # 同じvideo_idを持つ他の共有レコードがあるか確認
        remaining_shares = Share.query.filter_by(video_id=file_id).count()

        if remaining_shares == 0:
            # 共有レコードが他に存在しない場合　GCSからファイル削除
            try:
                gcs_client = storage.Client()
                bucket = gcs_client.bucket("mc_shared")
                blob = bucket.blob(share_record.gcs_file_path)
                blob.delete()
                logging.info(f"GCSファイルを削除しました: {share_record.gcs_file_path}")
            except NotFound:
                logging.warning(
                    f"GCSファイルが見つかりません: {share_record.gcs_file_path}"
                )
            except Exception as gcs_error:
                logging.error(f"GCSファイル削除エラー: {str(gcs_error)}")
                # GCSファイルの削除に失敗しても、共有自体は解除されているのでエラーは返さない

        return jsonify({"status": "success", "message": "共有解除完了"})

    except Exception as e:
        db.session.rollback()
        logging.error(f"予期せぬエラー: {str(e)}")
        return (
            jsonify({"status": "error", "message": "予期せぬエラーが発生しました"}),
            500,
        )


# ajax：ステータス取得
@app.route("/ajax/status")
@login_required
def get_status():
    id = request.args.get("id")
    if id is not None:
        record = (
            db.session.query(Summary.status, Summary.processed_percent)
            .filter(Summary.id == id)
            .first()
        )

        if record:
            return dict(step=record.status, pc=record.processed_percent)
        else:
            return {"error": "レコードが存在しません"}, 404

    return {"error": "IDがありません"}, 400


# ajax：日付変更
@app.route("/ajax/changedate", methods=["POST"])
@login_required
def changedate():
    data = request.get_json()
    id = data.get("id")
    date = data.get("date")

    if date and id:
        try:
            summary = db.session.query(Summary).filter_by(id=id).first()
            if summary:
                # レコードの値を更新
                summary.date = date

                # 変更をデータベースにコミット
                db.session.commit()
                print(f"Status update succeeded: [id]{id}, [date]{date}")
                return {"success": f"[id]{id}, [date]{date}"}
            else:
                print("No record")
                return {"error": "no record."}, 400
        except SQLAlchemyError as e:
            print("error", str(e))
            db.session.rollback()
            return {"error": "DB Error."}, 400

    return {"error": "error on ID or date"}, 400


# ajax：コメント変更
@app.route("/ajax/editcomment", methods=["POST"])
@login_required
def editcomment():
    id = request.form.get("id")
    comment = request.form.get("comment")

    if comment and id:
        try:
            summary = db.session.query(Summary).filter_by(id=id).first()
            if summary:
                # レコードの値を更新
                summary.comment = comment

                # 変更をデータベースにコミット
                db.session.commit()
                print(f"Status update succeeded: [id]{id}, [comment]{comment}")
                return redirect(url_for("video", file_id=id))
            else:
                print("No record")
                return {"error": "no record."}, 400
        except SQLAlchemyError as e:
            print("error", str(e))
            db.session.rollback()
            return {"error": "DB Error."}, 400

    return {"error": "error on ID or date"}, 400


# ajax：議事録変更
@app.route("/ajax/editsummary", methods=["POST"])
@login_required
def editsummary():
    data = request.get_json()
    id = data.get("id")
    summarydata = data.get("summary")

    if summarydata and id:
        try:
            summary = db.session.query(Summary).filter_by(id=id).first()
            if summary:
                # レコードの値を更新
                summary.summary = summarydata

                # 変更をデータベースにコミット
                db.session.commit()
                print(f"Status update succeeded: [id]{id}, [summary]{summarydata}")
                return {"success": summarydata}
            else:
                print("No record")
                return {"error": "no record."}, 400
        except SQLAlchemyError as e:
            print("error", str(e))
            db.session.rollback()
            return {"error": "DB Error."}, 400

    return {"error": "error on ID or summary"}, 400


# ajax：ユーザー情報取得
@app.route("/ajax/user")
@login_required
def get_user():
    user = get_userdata()

    if user:
        user_data = {
            "id": user.id,
            "name": user.name,
            "pic": user.pic,
            "role": user.role,
        }
        return user_data
    else:
        return None


def get_userdata():
    if "userdata" in session:
        token = session["userdata"]
        user = User.query.filter_by(id=token["id"]).first()
        return user
    else:
        return None


@app.route("/res/<path>")
@login_required
def send(path):
    return send_from_directory(app.config["UPLOAD_FOLDER"], path)


@app.route("/pic/<path>")
@login_required
def pic(path):
    return send_from_directory(app.config["STATIC_FOLDER"], path)


# init
if __name__ == "__main__":
    app.run(use_reloader=False, debug=True)
