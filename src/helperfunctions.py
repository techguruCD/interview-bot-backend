import re
import jwt
import bcrypt
import pinecone
import psycopg2
import traceback
from flask import Flask
from flask_cors import CORS
from constants import *
from config import *
from datetime import datetime, timedelta
from flask import jsonify
from psycopg2 import errors


def get_logger(name, level="DEBUG"):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    return logger


def initialize_app():
    app = Flask(__name__)
    # CORS(app=app, origins=["*"], expose_headers=["*"], vary_header=True)
    CORS(app)
    # CORS(app, resources={r"/*": {"origins": "*"}})
    # CORS(app, resources={r"/*": {"origins": "*", "allow_headers": "*", "methods": "*"}})
    logger = get_logger(__name__)
    app.config["FILE_UPLOADS"] = FILE_LOCATION
    app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
    return app, logger


# db functions
def connect_db(logger):
    connection = None
    try:
        connection = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
        )
        logger.info("Connected to database")

    except psycopg2.Error as e:
        logger.exception(
            f"Error in connecting database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
    return connection


def connect_pinecone(logger):
    try:
        index_name = "text-embeddings"
        pinecone.init(api_key=PINECONE_API_KEY, environment="gcp-starter")
        indexes = pinecone.list_indexes()
        if index_name in indexes:
            pinecone.delete_index(index_name)
        if index_name not in indexes:
            pinecone.create_index(index_name, dimension=384, metric="cosine")
            pinecone.describe_index(index_name)
        index = pinecone.Index(index_name)
        logger.info("connected to pinecone")
    except pinecone.core.exceptions.PineconeProtocolError as e:
        logger.exception(
            f"Failed to connect to Pinecone:, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )

    return index


def tables(cursor, connection, logger):
    if not (check_table(cursor, "user", logger, connection)):
        create_table_user(logger, cursor, connection)
    if not (check_table(cursor, "profile", logger, connection)):
        create_table_profile(logger, cursor, connection)
    if not (check_table(cursor, "bot", logger, connection)):
        create_table_bot(logger, cursor, connection)
    if not (check_table(cursor, "admin", logger, connection)):
        create_table_admin(logger, cursor, connection)


def refresh_connection(connection, cursor, logger):
    cursor.close()
    connection.close()
    connect_db(logger)


def create_table_user(logger, cursor, connection):
    try:
        create_table_sql = """
        CREATE TABLE "user" (
        user_id VARCHAR(255) PRIMARY KEY NOT NULL,
        email VARCHAR(255),
        social_id VARCHAR(255),
        password VARCHAR(255),
        full_name VARCHAR(255) NOT NULL,
        role VARCHAR(255),
        status VARCHAR(255),
        login_type VARCHAR(255) DEFAULT 'email' CHECK (login_type IN ('email', 'google', 'linkedin'))
        );
        """
        cursor.execute(create_table_sql)
        connection.commit()
        logger.info("user Table is created")
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
    except psycopg2.Error as e:
        logger.exception(
            f"Error in creating user table in database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )


def create_table_bot(logger, cursor, connection):
    try:
        create_table_sql = """
            CREATE TABLE "bot" (
            user_id VARCHAR(255) PRIMARY KEY NOT NULL,
            tone VARCHAR(200),
            style VARCHAR(200),
            prompt text,
            strength_weakness text,
            about text,
            challenges  text
            );
            """
        cursor.execute(create_table_sql)
        connection.commit()
        logger.info("bot Table is created")
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)

    except psycopg2.Error as e:
        logger.exception(
            f"Error in creating bot table in database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )


def create_table_profile(logger, cursor, connection):
    try:
        create_table_sql = """
            CREATE TABLE "profile" (
            user_id VARCHAR(255) PRIMARY KEY NOT NULL,
            about text,
            headline VARCHAR(300),
            full_name VARCHAR(100),
            linkedin VARCHAR(100),
            website VARCHAR(100),
            avatar VARCHAR(200),
            profile_photo VARCHAR(665600)
            );
            """
        cursor.execute(create_table_sql)
        connection.commit()
        logger.info("profile Table is created")
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)

    except psycopg2.Error as e:
        logger.exception(
            f"Error in creating profile table in database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )


def create_table_admin(logger, cursor, connection):
    try:
        create_table_sql = """
            CREATE TABLE "admin" (
            admin_id VARCHAR(255) PRIMARY KEY NOT NULL,
            role VARCHAR(300),
            full_name VARCHAR(100),
            password VARCHAR(50)
            );
            """
        cursor.execute(create_table_sql)
        connection.commit()
        logger.info("admin Table is created")
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)

    except psycopg2.Error as e:
        logger.exception(
            f"Error in creating admin table in database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )


def check_admin(cursor, admin_id):
    check_user_sql = "SELECT COUNT(*) FROM admin WHERE admin_id = %s"
    cursor.execute(check_user_sql, (admin_id,))
    user_count = cursor.fetchone()[0]

    if user_count > 0:
        return "admin already exist"
    else:
        return True


def insert_profile(
    logger,
    cursor,
    connection,
    user_id,
    full_name,
    headline=None,
    linkedin=None,
    website=None,
    about=None,
    avatar=None,
    profile_photo=None,
):
    try:
        insert_sql = """
                        INSERT INTO profile (user_id ,about, headline, full_name, linkedin, website, avatar, profile_photo)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """
        cursor.execute(
            insert_sql,
            (
                user_id,
                about,
                headline,
                full_name,
                linkedin,
                website,
                avatar,
                profile_photo,
            ),
        )
        connection.commit()
        logger.info("value inserted in profile Table")

    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
    except psycopg2.Error as e:
        logger.exception(
            f"Error in inserting data in profile table, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )


def insert_admin(logger, cursor, connection, admin_id, full_name, role, password):
    try:
        insert_sql = """
                        INSERT INTO admin (admin_id ,role, full_name,password )
                        VALUES (%s, %s, %s, %s)
                    """
        cursor.execute(
            insert_sql,
            (admin_id, role, full_name, password),
        )
        connection.commit()
        logger.info("value inserted in admin Table")

    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
    except psycopg2.Error as e:
        logger.exception(
            f"Error in inserting data in admin table, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )


def insert_bot(
    logger,
    cursor,
    connection,
    user_id,
    about=None,
    prompt_=None,
    style=None,
    tone=None,
    s_w=None,
    challenge=None,
):
    try:
        query = """
                       SELECT COUNT(*) FROM bot WHERE user_id = %s
                    """
        cursor.execute(query, (user_id,))
        user_count = cursor.fetchone()[0]

        if user_count > 0:
            update_query = """
            UPDATE "bot"
            SET tone=%s, style= %s, prompt=%s, strength_weakness=%s,about=%s, challenges=%s
            WHERE user_id = %s;
            """
            cursor.execute(
                update_query,
                (tone, style, prompt_, s_w, about, challenge, user_id),
            )
            connection.commit()
            logger.info("bot updated")

        else:
            insert_sql = """
                        INSERT INTO "bot" (user_id, tone, style,prompt, strength_weakness,about,challenges)
                        VALUES (%s, %s, %s, %s, %s, %s,%s )
                    """
            cursor.execute(
                insert_sql, (user_id, tone, style, prompt_, s_w, about, challenge)
            )
            connection.commit()
            logger.info("value inserted in bot Table")

    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
    except psycopg2.Error as e:
        logger.exception(
            f"Error in inserting data in bot table, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )


def insert_user(
    logger,
    cursor,
    connection,
    user_id,
    name,
    pwd,
    email=None,
    social_id=None,
    role=None,
    status=None,
    login_type=None,
):
    try:
        insert_sql = """
                        INSERT INTO "user" (user_id, email,social_id,password, full_name, role, status, login_type)
                        VALUES (%s, %s, %s, %s, %s, %s , %s,%s)
                    """
        cursor.execute(
            insert_sql,
            (user_id, email, social_id, pwd, name, role, status, login_type),
        )
        connection.commit()
        logger.info("value inserted in user Table")

    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
    except psycopg2.Error as e:
        logger.exception(
            f"Error in inserting data in user table, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )


def update_profile(
    cursor,
    connection,
    logger,
    id,
    about,
    headline,
    full_name,
    linkedin,
    website,
    avatar,
    profile_photo,
):
    try:
        update_query = """
        UPDATE "profile"
        SET about= %s, headline= %s, full_name=%s, linkedin=%s,website=%s, avatar=%s, profile_photo=%s
        WHERE user_id = %s;
        """
        cursor.execute(
            update_query,
            (about, headline, full_name, linkedin, website, avatar, profile_photo, id),
        )
        connection.commit()
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
    except Exception as e:
        logger.exception(
            f"An error occurred while fetching data from database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )


def check_id_profile(cursor, id, logger, connection):
    try:
        select_sql = """
                SELECT * FROM "profile" WHERE user_id=%s;
            """
        cursor.execute(select_sql, (id,))
        count = cursor.fetchall()
        if count == []:
            return False, " "
        else:
            return True, count
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
        return False, "Error: " + str(tr_error)

    except psycopg2.Error as e:
        logger.exception(
            f"An error occurred while fetching data from database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return False, "Error: " + str(e)


def check_table(cursor, table, logger, connection):
    try:
        query = f"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = %s)"
        cursor.execute(query, (table,))
        table_exists = cursor.fetchone()[0]
        return table_exists
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)

    except Exception as e:
        message = "An error occurred:  " + str(e)
        logger.exception(
            f"An error occurred while fetching data from database: \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
    return None


def check_email(cursor, email, logger, connection):
    try:
        select_sql = """
                SELECT * FROM "user" WHERE email=%s;
            """
        cursor.execute(select_sql, (email,))
        count = cursor.fetchall()
        logger.info(count)

        if not count:
            return False
        else:
            return True
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
        return False

    except psycopg2.Error as e:
        logger.exception(
            f"An error occurred while fetching data from database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return False


def check_socialid(cursor, login_type, socialid, logger, connection):
    try:
        select_sql = """
                SELECT * FROM "user" WHERE  login_type= %s AND  social_id= %s ;
            """
        cursor.execute(
            select_sql,
            (
                login_type,
                socialid,
            ),
        )
        data = cursor.fetchall()
        if not data:
            return [False, "No user"]
        else:
            return [True, data]
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
    except psycopg2.Error as e:
        logger.exception(
            f"An error occurred while fetching data from database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return ["Error: ", str(e)]


def check_id(cursor, logger, id, connection):
    try:
        insert_sql = """
                    SELECT * FROM "user" WHERE user_id=%s;

                """
        cursor.execute(insert_sql, (id,))
        data = cursor.fetchall()
        if not data:
            return False
        else:
            return True
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)

    except psycopg2.Error as e:
        logger.exception(
            f"An error occurred while fetching data from database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return False


def check_status(cursor, logger, id, connection):
    try:
        insert_sql = """
                    SELECT status FROM "user" WHERE user_id=%s;

                """
        cursor.execute(insert_sql, (id,))
        data = cursor.fetchall()
        if data == "1":
            return True
        else:
            return False
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
    except psycopg2.Error as e:
        logger.exception(
            f"An error occurred while fetching data from database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return False


def get_data(cursor, logger, email, login_type, connection):
    try:
        insert_sql = """
                    SELECT * FROM "user" WHERE email=%s AND login_type=%s;

                """
        cursor.execute(insert_sql, (email, login_type))
        data = cursor.fetchall()
        if not data:
            return False
        else:
            return data
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
    except psycopg2.Error as e:
        logger.exception(
            f"An error occurred while fetching data from database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return False


def get_prompt(cursor, logger, id, connection):
    try:
        select_sql = """
                SELECT * FROM "bot" WHERE  user_id = %s;
            """
        cursor.execute(select_sql, (id,))
        data = cursor.fetchall()
        logger.info(data)
        if not data:
            return False, " "
        if data[0][3] == "Null":
            return True, PROMPT
        else:
            prompt_ = PromptTemplate(
                input_variables=["context", "question"],
                template=data[0][3],
            )
            return True, prompt_

    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
        return False, " "
    except psycopg2.Error as e:
        logger.exception(
            f"An error occurred while fetching data from database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return False, " "


def get_data_profile(cursor, logger, id, connection):
    try:
        insert_sql = """
                    SELECT * FROM "profile" WHERE user_id=%s;
                """
        cursor.execute(insert_sql, (id,))
        data = cursor.fetchall()
        if data == []:
            return False, data
        else:
            return True, data
    except errors.TransactionRollbackError as tr_error:
        refresh_connection(connection, cursor, logger)
        return False, str(tr_error)
    except psycopg2.Error as e:
        logger.exception(
            f"An error occurred while fetching data from database, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return False, str(e)


# other functions


def hash_password(password, logger):
    try:
        bytes = password.encode("utf-8")
        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(bytes, salt)
        hash = hash.decode("utf8")
        return hash
    except Exception as e:
        logger.exception(
            f"An error occurred while hashing password, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return "Error: " + str(e)


def check_password(hashed_password, password, logger):
    try:
        userBytes = password.encode("utf-8")
        hashed_password = hashed_password.encode("utf-8")
        result = bcrypt.checkpw(userBytes, hashed_password)
        return result
    except Exception as e:
        logger.exception(
            f"An error occurred while decoding password, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return "Error: " + str(e)


def generate_jwt_token(user_id, logger):
    try:
        payload = {"user_id": user_id, "exp": datetime.utcnow() + timedelta(days=10)}
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
        return token
    except Exception as e:
        logger.exception(
            f"An error occurred while generating jwt Token, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return "Error: " + str(e)


def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError as e:
        message = "error in decoding jwt token: " + str(e)
        return message
    except jwt.InvalidTokenError as e:
        message = "Error in jwt Invalid Token: " + str(e)
        return message


# checks
def check_null(value):
    if not value:
        return True
    else:
        return False


def check_length(value):
    if len(value) >= 8:
        return False
    else:
        return True


def regex_checker(value, regex_type):
    descriptive = r"^(?!\s$)(?![-/]+$)[a-zA-Z0-9.,-_/'\"()!#$%^&+={}[]|:;<>?@ ]+$"
    simple = r"^[a-zA-Z0-9_]{3,20}$"
    number = r"^[+\d][\d +-]$"
    special = r"^(?!\s*$)(?![-/]+$)[a-zA-Z0-9.-/' ]+$"
    email = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if regex_type == "descriptive":
        return bool(re.match(descriptive, value))
    elif regex_type == "simple":
        return bool(re.match(simple, value))
    elif regex_type == "number":
        return bool(re.match(number, value))
    elif regex_type == "special":
        return bool(re.match(special, value))
    elif regex_type == "email":
        return bool(re.match(email, value))
    else:
        return False


def success_response(data, message, code=200):
    response_dict = {"statusCode": "", "message": "", "data": {}}
    response_dict["statusCode"] = code
    response_dict["data"] = data
    response_dict["message"] = message
    return jsonify(response_dict), code


def error_response(message, data={}, code=400):
    response_dict = {"statusCode": "", "message": "", "data": {}}
    response_dict["statusCode"] = code
    response_dict["data"] = data
    response_dict["message"] = "error: " + message
    return jsonify(response_dict), code
