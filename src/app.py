import uuid
import traceback
from flask import request, g
import requests
from flask_jwt_extended import JWTManager
from auth_middleware import token_required
from helperfunctions import *
from config import *
from constants import *
from psycopg2 import sql
from chatbot import *
from flask import send_from_directory
from werkzeug.utils import secure_filename
from conversation import create_conversation
from indexes import create_indexes, clear_indexes
import time

ACTIVE_SESSIONS = {}
LLM_OBJECT = get_llm_object()
app, logger = initialize_app()
jwt = JWTManager(app)
index = connect_pinecone(logger)
index_name = "text-embeddings"
try:
    connection = connect_db(logger)
    cursor = connection.cursor()
    tables(cursor, connection, logger)
except Exception as e:
    logger.critical(f"{str(e)}", exc_info=True)


@app.route("/signup_email", methods=["POST"])
def signup_email():
    try:
        # get data
        data = request.get_json()
        full_name = data["name"]
        email = data["email"]
        password = data["password"]
        role = "user"
        status = "1"

        # check null values
        if check_null(email) or check_null(password) or check_null(full_name):
            return error_response("null data")
        # check length of password

        if check_length(password):
            return error_response("password should be greater than 8 digits")
        # check email format
        if not regex_checker(email, "email"):
            return error_response("incorrect email")
        # check if email already registered
        response = check_email(cursor, email, logger, connection)
        if response == True:
            return error_response("user already exists")
        # insert data in database and return jwt token
        elif response == False:
            user_id = str(uuid.uuid4())
            if len(full_name) > 255:
                return error_response("user name should be less than 255 characters")
            if len(password) > 255:
                return error_response("password should be less than 255 characters")
            if len(email) > 255:
                return error_response("email should be less than 255 characters")

            password = hash_password(password, logger)
            insert_user(
                logger,
                cursor,
                connection,
                user_id,
                full_name,
                password,
                email,
                None,
                role,
                status,
                "email",
            )
            jwt_token = generate_jwt_token(user_id, logger)
            return success_response({"token": jwt_token}, "successfuly sigup")
        else:
            return error_response(str(response))
    except Exception as e:
        logger.exception(
            f"An error occurred in signup email endpoint, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return error_response(str(e))


@app.route("/social_login_google", methods=["POST"])
def signup_google():
    try:
        data = request.get_json()
        oauth_token = data["access_token"]
        # check null
        if check_null(oauth_token):
            return error_response("null data")

        client_id = CLIENT_ID_GOOGLE
        # Construct the token validation request
        token_validation_url = GOOGLE_URL
        params = {"access_token": oauth_token}
        # Make the token validation request
        response = requests.get(token_validation_url, params=params)
        validation_data = response.json()

        # Check if the validation response indicates success
        if "error_description" not in validation_data:
            if validation_data["aud"] == client_id:
                social_id = validation_data["sub"]
                email = validation_data["email"]
            else:
                return error_response("invalid token: incorrect audience")
        else:
            exception_message = "Invalid token: " + \
                validation_data["error_description"]
            logger.error(exception_message)
            return error_response(exception_message)
    except Exception as e:
        logger.exception(
            f"An error occurred in social login google endpoint, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return error_response(str(e))

    if social_id:
        try:
            response, data = check_socialid(
                cursor, "google", social_id, logger, connection
            )
            # check authorized user
            if response:
                if (data[0][5] == "user") and (data[0][6] == "1"):
                    jwt_token = generate_jwt_token(data[0][0], logger)
                    return success_response(
                        {"token": jwt_token}, "logged in successfuly"
                    )
                # unauthorized
                else:
                    return error_response("unauthorized", code=401)
            elif response == False:
                user_id = str(uuid.uuid4())
                if len(email) > 255:
                    return error_response("email should be less than 255 characters")
                name = None
                insert_user(
                    logger,
                    cursor,
                    connection,
                    user_id,
                    name,
                    None,
                    email,
                    social_id,
                    "user",
                    "1",
                    "google",
                )
                jwt_token = generate_jwt_token(user_id, logger)
                return success_response({"token": jwt_token}, "user added")
            else:
                return error_response(response)

        except Exception as e:
            logger.exception(
                f"Error in signup_google endpoint, \n TRACEBACK:{traceback.format_exc()}",
                exc_info=True,
            )
            return error_response(str(e))


@app.route("/social_login_linkedin", methods=["POST"])
def signup_linkedin():
    try:
        data = request.get_json()
        oauth_token = data["access_token"]
        # check null
        if check_null(oauth_token):
            return error_response("null data")
        client_id = CLIENT_ID_LINKEDIN
        # Construct the token validation request
        token_validation_url = LINKEDIN_URL
        # params = {"access_token": oauth_token}
        headers = {"Authorization": f"Bearer {oauth_token}"}
        # Make the token validation request
        response = requests.get(token_validation_url, headers=headers)
        validation_data = response.json()

        # Check if the validation response indicates success
        if "error_description" not in validation_data:
            email = validation_data["email"]
        else:
            exception_message = "Invalid token: " + \
                validation_data["error_description"]
            return error_response(exception_message)
    except Exception as e:
        logger.exception(
            f"An error occurred in social login linkedin endpoint, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return error_response(str(e))

    if email:
        try:
            response, data = check_email(cursor, email, logger, connection)
            if response:
                if (data[0][5] == "user") and (data[0][6] == "1"):
                    jwt_token = generate_jwt_token(data[0][0], logger)
                    return success_response(
                        {"token": jwt_token}, "logged in successfuly"
                    )
                # unauthorized
                else:
                    logger.info("unauthorized")
                    return error_response("unauthorized", code=401)

            elif response == False:
                user_id = str(uuid.uuid4())
                if len(email) > 255:
                    return error_response("email should be less than 255 characters")
                name = None
                insert_user(
                    logger,
                    cursor,
                    connection,
                    user_id,
                    name,
                    None,
                    email,
                    None,
                    "user",
                    "1",
                    "linkedin",
                )
                jwt_token = generate_jwt_token(user_id, logger)
                return success_response({"token": jwt_token}, "user added")
            else:
                return error_response(str(response))

        except Exception as e:
            logger.exception(
                f"Error in signup linkedin endpoint, \n TRACEBACK:{traceback.format_exc()}",
                exc_info=True,
            )
            return error_response(str(e))


@app.route("/login_email", methods=["POST"])
def login_email():
    try:
        data = request.get_json()
        email = data["email"]
        password = data["password"]
        login_type = "email"
        # check null values
        if check_null(email) or check_null(password):
            return error_response("null data")

        # fetch data from database
        data = get_data(cursor, logger, email, login_type, connection)

        # if it does not exists
        if data == False:
            return error_response("no record found", data={"message": data})
        # if data found
        else:
            # check authorized user
            if (data[0][5] == "user") and (data[0][6] == "1"):
                # if password is correct
                if check_password(data[0][3], password, logger):
                    jwt_token = generate_jwt_token(data[0][0], logger)
                    logger.info("successfully login")
                    return success_response({"token": jwt_token}, "successfully login")
                # password not correct
                else:
                    logger.info("incorrect password")
                    return error_response("incorrect password")
            # user not authorized
            else:
                logger.info("unauthorized")
                return error_response("unauthorized", code=401)
    except Exception as e:
        logger.exception(
            f"Error in login_email endpoint, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return error_response(str(e))


@app.route("/setup_bot", methods=["POST"])
@token_required
def setup_bot():
    # data = request.get_json
    print('hiiii', request.form)
    try:
        tone = request.form["tone"]
        style = request.form["style"]
        s_w = request.form["strength_weakness"]
        challenge = request.form["challenges"]
        cv = request.files["cv"]
        about = request.form["about"]
        name = request.form["name"]
        user_id = g.token
        user_id = user_id["user_id"]
        check = check_id(cursor, logger, user_id, connection)
        if check == True:
            if not (cv.filename.endswith(".pdf") or cv.filename.endswith(".docx")):
                logger.info("incorrect CV format")
                return error_response(
                    "this file format is not supported", data={"user": user_id}
                )
            if check_null(name):
                return error_response("name is null")
            else:
                if len(tone) > 200:
                    return error_response("tone should be less than 200 characters")
                if len(style) > 200:
                    return error_response("style should be less than 200 characters")

                prompt_ = prompt(tone, style, name)

                text = (
                    "About: \n"
                    + about
                    + "\nStrength and weakness \n"
                    + s_w
                    + "\n challenges \n"
                    + challenge
                )
                insert_bot(
                    logger,
                    cursor,
                    connection,
                    user_id,
                    about,
                    prompt_,
                    style,
                    tone,
                    s_w,
                    challenge,
                )
                filepath = os.path.join(FILE_LOCATION, cv.filename)
                cv.save(filepath)
                doc = create_document(filepath, text, user_id, logger)
                emd = get_embedding()
                response = save_embedding(
                    doc, user_id, emd, index_name, logger)
                os.remove(filepath)
                logger.info(f"Deleted CSV file: {filepath}")
                response = True

                if response:
                    logger.info("setupbot: ")
                    return success_response({}, "bot is ready")
                else:
                    return error_response("error in saving embeddings")

        elif check == False:
            return error_response("no record found against this id")

        else:
            return error_response(str(check))

    except Exception as e:
        logger.exception(
            f"Error in setup_bot endpoint, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return error_response(str(e))


@app.route("/bot", methods=["GET"])
@token_required
def get_bot():
    try:
        user_id = g.token
        user_id = user_id["user_id"]
        check = check_id(cursor, logger, user_id, connection)
        if check:
            success, prompt_ = get_prompt(cursor, logger, user_id, connection)
            prompt_ = PROMPT

            if success:
                conversation_id_chain = initialize_qa_chain(
                    LLM_OBJECT, prompt=prompt_)
                logger.info("chain initiallized... ")
                ACTIVE_SESSIONS[user_id] = conversation_id_chain

                return success_response({}, "conversation response received")

            else:
                logger.info("no data found against this id {}".format(user_id))
                return error_response("no data")

        else:
            return error_response(str(check))

    except Exception as e:
        logger.exception(
            f"Error in bot endpoint, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return error_response(str(e))


@app.route("/bot", methods=["POST"])
@token_required
def bot():
    try:
        user_id = g.token
        user_id = user_id["user_id"]
        data = request.get_json()
        check = check_id(cursor, logger, user_id, connection)
        if check:
            question = data["question"]
            if check_null(question):
                return error_response("question is null")
            if user_id not in ACTIVE_SESSIONS:
                return error_response("session is not initialized")
            chain = ACTIVE_SESSIONS[user_id]
            if not chain:
                return error_response("conversation is not initialized")
            emd = get_embedding()
            success, doc = get_embedding_pinecone(
                user_id, index_name, emd, logger)
            if success:
                response = get_response(question, chain, doc)
                return success_response(str(response), "AI")
            else:
                return error_response(str(response))
        elif check == False:
            return error_response("no record found against this id")
        else:
            return error_response(str(check))
    except Exception as e:
        logger.exception(
            f"Error in bot endpoint, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return error_response(str(e))


@app.route("/profile", methods=["POST"])
@token_required
def profile():
    try:
        data = request.get_json()
        headline = data["headline"]
        full_name = data["full_name"]
        linkedin = data["linkedin"]
        website = data["website"]
        about = data["about"]
        avatar = data["avatar"]
        profile_photo = data["image"]
        user_id = g.token
        user_id = user_id["user_id"]
        # check user name is null or not
        if check_null(full_name):
            return error_response("null input")
        if not regex_checker(full_name, "special"):
            return error_response("incorrect format of full_name")
        if len(profile_photo) > 665600:
            return error_response("Profile photo is too big. Should be less than 500kb")
        if len(full_name) > 100:
            return error_response("user name should be less than 100 characters")
        if len(headline) > 200:
            return error_response("headline should be less than 200 characters")
        if len(linkedin) > 100:
            return error_response("linkedin link should be less than 100 characters")
        if len(website) > 100:
            return error_response("website link should be less than 100 characters")
        if len(avatar) > 200:
            return error_response("linkedin link should be less than 200 characters")

        # check id in database

        check = check_id(cursor, logger, user_id, connection)
        # if id insert data
        if check == True:
            success, data = check_id_profile(
                cursor, user_id, logger, connection)

            if success:
                if not headline:
                    headline = data[0][2]
                if not about:
                    about = data[0][1]
                if not linkedin:
                    linkedin = data[0][4]
                if not website:
                    website = data[0][5]
                if not avatar:
                    avatar = data[0][6]
                if not profile_photo:
                    profile_photo = data[0][7]

                update_profile(
                    cursor,
                    connection,
                    logger,
                    user_id,
                    about,
                    headline,
                    full_name,
                    linkedin,
                    website,
                    avatar,
                    profile_photo,
                )
                return success_response({}, "record updated")

            else:
                insert_profile(
                    logger,
                    cursor,
                    connection,
                    user_id,
                    full_name,
                    headline,
                    linkedin,
                    website,
                    about,
                    avatar,
                    profile_photo,
                )
                return success_response({}, "new user inserted")
        # user not found
        elif check == False:
            return error_response("no record found against this id")

        else:
            return error_response(str(check))
    except Exception as e:
        logger.exception(
            f"Error in profile endpoint, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return error_response(str(e))


@app.route("/profile", methods=["GET"])
@token_required
def get_profile():
    try:
        user_id = g.token
        user_id = user_id["user_id"]
        success, data = get_data_profile(cursor, logger, user_id, connection)
        if success:
            d = {
                # "user_id": data[0][0],
                "name": data[0][3],
                "about": data[0][1],
                "headline": data[0][2],
                "linkedin": data[0][4],
                "website": data[0][5],
                "avatar": data[0][6],
                "photo": data[0][7],
            }
            return success_response(d, "user data")
        else:
            return error_response("no data found")
    except Exception as e:
        logger.exception(
            f"Error in get profile endpoint, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return error_response(str(e))


@app.route("/terminate_bot", methods=["GET"])
@token_required
def terminate_bot():
    try:
        user_id = g.token
        user_id = user_id["user_id"]
        if user_id in ACTIVE_SESSIONS:
            del ACTIVE_SESSIONS[user_id]
            return success_response({}, "chat terminated")
        else:
            return success_response({}, "no chat session")
    except Exception as e:
        logger.exception(
            f"Error in terminate_bot endpoint, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return error_response(str(e))


@app.route("/public_profile", methods=["POST"])
def get_public_data():
    try:
        data = request.get_json()
        user_id = data["user_id"]
        success, data = get_data_profile(cursor, logger, user_id, connection)
        if success:
            d = {
                "name": data[0][3],
                "about": data[0][1],
                "headline": data[0][2],
                "linkedin": data[0][4],
                "website": data[0][5],
                "avatar": data[0][6],
                "photo": data[0][7],
            }
            return success_response(d, "user data")
        else:
            return error_response("no data found")
    except Exception as e:
        logger.exception(
            f"Error in public_profile endpoint, \n TRACEBACK:{traceback.format_exc()}",
            exc_info=True,
        )
        return error_response(str(e))
    
@app.route('/create_indexes', methods=['POST'])
def create_index():
    # Extract data from the request
    data = request.get_json()
    file_names = data['file_names']
    #how to get file with name of file_name in the assets folder?
    files = []
    for file_name in file_names:
        file_path = os.path.join('assets', file_name)
        files.append(file_path)
    
    pinecone_api_key = data['pinecone_api_key']
    pinecone_environment = data['pinecone_environment']
    pinecone_index_name = data['pinecone_index_name']
    openai_api_key = data['openai_api_key']

    # Call your existing function
    result = create_indexes(files, pinecone_api_key, pinecone_environment, pinecone_index_name, openai_api_key)
    print('result: ', result)

    # Return the result as JSON
    return jsonify(result)

@app.route('/clear_indexes', methods=['POST'])
def clear_index():
    print('called')
    # Extract data from the request
    data = request.get_json()
    pinecone_api_key = data['pinecone_api_key']
    pinecone_environment = data['pinecone_environment']
    pinecone_index_name = data['pinecone_index_name']

    # Call your existing function
    result = clear_indexes(pinecone_api_key, pinecone_environment, pinecone_index_name)

    # Return the result as JSON
    return jsonify(result)

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    query = data['query']
    chat_history = data['chat_history']
    pinecone_api_key = data['pinecone_api_key']
    pinecone_environment = data['pinecone_environment']
    pinecone_index_name = data['pinecone_index_name']
    openai_api_key = data['openai_api_key']
    prompt = data['prompt']

    result = create_conversation(query, pinecone_api_key, pinecone_environment, pinecone_index_name, openai_api_key, chat_history, prompt)

    return jsonify(result)

@app.route('/upload', methods=['POST'])
def upload_file():
    # Define the directory path
    dir_path = os.path.join('assets')

    # Check if the directory exists
    if not os.path.exists(dir_path):
        # Create the directory
        os.makedirs(dir_path)

    # Check if 'file' is in the uploaded files
    if 'file' in request.files:
        files = request.files.getlist('file')
        filenames = []
        for file in files:
            timestamp = int(time.time())
            filename = f"{timestamp}_{secure_filename(file.filename)}"
            file.save(os.path.join(dir_path, filename))
            filenames.append(filename)

        return jsonify({"filenames": filenames, "message": 'Files uploaded successfully'})
    
    return jsonify({"message": "No files uploaded"})


@app.route('/uploads/<filename>')
def upload(filename):
    dir_path = os.path.join('assets')
    return send_from_directory(dir_path, filename)


if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=APP_PORT, debug=True)
    except Exception as e:
        print(str(e))
    finally:
        cursor.close()
        connection.close()
