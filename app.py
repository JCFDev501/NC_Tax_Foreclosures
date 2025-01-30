import re
from datetime import datetime
import stripe
from flask import request, jsonify, redirect, url_for, make_response, render_template
from flask_login import login_required
from werkzeug.security import generate_password_hash
from api_utils import create_tax_foreclosure_history, update_user_purchase_status, update_developer_account, \
    update_developer_token, create_user_purchase_status, delete_user_purchase_status, check_permission
from auth_middleware import check_authentication_or_dev_token_required
from config import app, db, endpoint_secret, default_origins, secret_key, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, \
    base_url, frontend_url, GOOGLE_REQUEST
from log import log_error, log_info
from models import User, UserSchema, PaymentAccount, DeveloperAccount, DeveloperAccountSchema, FeatureStatus, \
    DevTokenStatus, DeveloperToken, DeveloperTokenSchema, TaxForeclosure, TaxForeclosureSchema, TaxForeclosureHistory, \
    TaxForeclosureHistorySchema, County, CountySchema, PaymentAccountSchema, AdminUser, AdditionalTaxForeclosureData
from stripe_api_manager import get_customer, create_new_customer, create_stripe_checkout_session_for_basic, \
    switch_to_developer, create_stripe_checkout_session_for_developer, switch_to_basic, get_subscription, get_product, \
    cancel_subscription
from user_login_manager import login, logout, get_current_user_info, get_google_provider_cfg, client, \
    get_google_user_info


def success_json():
    return {'success': True}


@app.route('/api/users/create', methods=['POST'])
def create_user():
    json_data = request.get_json()

    # Basic email and password validation
    email_regex = r'^\S+@\S+\.\S+$'
    if not re.match(email_regex, json_data.get('email', '')):
        return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400

    if len(json_data.get('password', '')) < 8:
        log_error('Password must be at least 8 characters long')
        return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters long'}), 400

    # Check if the user with the provided email already exists
    existing_user = User.query.filter_by(email=json_data['email']).first()

    if existing_user:
        log_error('The email you provided is already in use')
        return jsonify({'status': 'error', 'message': 'The email you provided is already in use'}), 409

    # Set the default role to 'user'
    role = 'user'

    # Check if admin password is provided and correct
    if json_data.get('admin_password'):
        admin_password = json_data['admin_password']
        admin = AdminUser.query.first()
        if admin and admin.check_password(admin_password):
            print("Authenticated successfully")
            role = 'admin'
        else:
            log_error('Admin password is incorrect')
            return jsonify({'status': 'error', 'message': 'Admin password is incorrect'}), 401

    try:
        # Hash the user's password
        hashed_password = generate_password_hash(json_data['password'])

        # Create a new user instance
        user = User(
            password=hashed_password,
            email=json_data['email'],
            name=json_data['name'],
            role=role,
            created_at=datetime.utcnow()
        )

        # Add the user to the session and commit
        db.session.add(user)
        db.session.commit()

        # Serialize the user object (excluding sensitive fields)
        user_schema = UserSchema()
        dump = user_schema.dump(user)

        return_val = success_json()
        return_val.update({'user': dump})

        log_info('User created successfully')
        return return_val, 201

    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        log_error(f"Error creating user: {e}")
        return jsonify({'status': 'error', 'message': 'An error occurred while creating the user'}), 500


@app.route('/api/poll_google_request_result', methods=['GET'])
def poll_google_request_result():
    # Check if request is processed
    result = GOOGLE_REQUEST.get_request_process()
    # return result
    return jsonify({"request_processed": result})


@app.route('/api/users/create_with_google_account', methods=['GET'])
def create_user_with_google_account():
    # Get the Google OAuth provider configuration
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Construct the redirect URI dynamically based on the current environment
    redirect_uri = f"{request.host_url}api/users/create_with_google_account_callback"

    # Use the OAuth client library to construct the login request
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=redirect_uri,
        scope=["openid", "email", "profile"],
    )

    # Make sure we reset this so we can process new request
    GOOGLE_REQUEST.reset()

    # Return the constructed request URI as JSON
    return jsonify({"request_uri": request_uri})



@app.route('/api/users/create_with_google_account_callback')
def create_user_with_google_account_callback():
    userinfo_response = get_google_user_info()

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        users_name = userinfo_response.json()["given_name"]

        # Hash the user's password
        hashed_password = generate_password_hash(unique_id)

        # Check if the user with the provided email already exists
        existing_user = User.query.filter_by(email=users_email).first()

        if existing_user:
            log_error('The email you provided is already in use')
            return jsonify({'status': 'error', 'message': 'The email you provided is already in use'}), 400

        # Create a new user instance
        user = User(
            password=hashed_password,
            email=users_email,
            name=users_name,
            role="user",
            created_at=datetime.utcnow()
        )

        # Add the user to the session and commit
        db.session.add(user)
        db.session.commit()

        # Serialize the user object (excluding sensitive fields)
        user_schema = UserSchema()
        dump = user_schema.dump(user)

        return_val = success_json()
        return_val.update({'user': dump})

        log_info('User created successfully')

        # After successful user creation, set google_request_process to true
        GOOGLE_REQUEST.process()

    else:
        return "User email not available or not verified by Google.", 400


@app.route('/api/users/list', methods=['GET'])
@login_required
def list_users():
    # Get the currently logged-in user
    success, user_or_message = get_current_user_info()

    user = user_or_message
    user_role = user['role']

    permission = check_permission('/api/users/list', user_role)
    if not permission:
        log_error('You do not have permission to access this resource')
        return jsonify({'status': 'error', 'message': 'You do not have permission to access this resource'}), 403

    # Retrieve all records from the users table
    users = User.query.all()

    if users:
        # Serialize the list of foreclosures
        schema = UserSchema(many=True)
        users_list = schema.dump(users)

        log_info('Users listed successfully')
        return jsonify({'status': 'success', 'users': users_list}), 200

    # Return 404 if no records are found
    log_info('No users found')
    return jsonify({'status': 'error', 'message': 'No users found'}), 404

@app.route('/api/users/login', methods=['POST'])  # Use 'POST' with uppercase
def login_user():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    # Call the login method
    success, message = login(email, password)


    if success:
        log_info('User logged in successfully')
        return jsonify(success=success, message=message), 200
    else:
        log_error('Login failed')
        return jsonify(success=success, message=message), 401  # Return a 401 Unauthorized status for failed login


@app.route('/api/users/login_with_google_account', methods=['GET'])
def login_user_with_google_account():
    # Get the Google OAuth provider configuration
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Dynamically generate the redirect URI based on the environment
    redirect_uri = f"{request.host_url}api/users/login_with_google_account_callback"

    # Use the OAuth client library to construct the login request
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=redirect_uri,
        scope=[
            "openid",
            "email",
            "profile"
        ],
    )

    # Make sure we reset this so we can process new request
    GOOGLE_REQUEST.reset()

    # Return the constructed request URI as JSON
    return jsonify({"request_uri": request_uri})


@app.route('/api/users/login_with_google_account_callback')
def login_user_with_google_account_callback():
    userinfo_response = get_google_user_info()

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]

        email = users_email
        password = unique_id

        # Call the login method
        success, message = login(email, password)

        if success:
            log_info('User logged in successfully')

            # After successful user creation, set google_request_process to true
            GOOGLE_REQUEST.process()
        else:
            return jsonify(success=success, message=message), 401  # Return a 401 Unauthorized status for failed login

    else:
        return "User email not available or not verified by Google.", 400


@app.route('/api/users/logout', methods=['POST'])
def logout_user():
    # Call the logout method
    success, message = logout()

    if success:
        log_info('User logged out successfully')
        return jsonify(success=success, message=message), 200
    else:
        log_info('Logout failed')
        return jsonify(success=success, message="Logout failed."), 400  # In case something goes wrong


@app.route('/api/users/current_user', methods=['GET'])
def get_current_user():
    success, data_or_message = get_current_user_info()

    if success:
        log_info('Current user retrieved successfully')
        return jsonify(success=True, user=data_or_message), 200
    else:
        log_error('No user is logged in')
        return jsonify(success=False, message=data_or_message), 401  # Return 401 Unauthorized if no user is logged in


@app.route('/api/developer_account/create', methods=['POST'])
@login_required
def create_developer_account():
    # Get the currently logged-in user
    success, user_or_message = get_current_user_info()

    if not success:
        log_error('You must be logged in to create a developer account')
        return jsonify({'status': 'error',
                        'message': 'You must be logged in to create a developer account'}), 401  # We should never hit this

    user = user_or_message
    user_id = user['id']

    # Check to see if we have the right type of subscription
    payment_account = PaymentAccount.query.filter_by(user_id=user_id).first()
    if not payment_account:
        log_error('You do not have a payment_account')
        return jsonify({'error': 'You do not have a payment_account'}), 401

    has_dev_sub = False
    user_purchase_statuses = payment_account.user_purchase_statuses
    for user_purchase_status in user_purchase_statuses:
        if user_purchase_status.feature_type == "Developer Subscription":
            log_info('User has a developer subscription')
            has_dev_sub = True

    if not has_dev_sub:
        log_error('You do not have a developer subscription')
        return jsonify({'status': 'error', 'message': 'You do not have a developer subscription'}), 401

    # Check if the user already has a developer account
    existing_account = DeveloperAccount.query.filter_by(user_id=user_id).first()

    if existing_account:
        log_error('User already has a developer account')
        return jsonify({'status': 'error', 'message': 'User already has a developer account'}), 409

    # create the account with the json data
    developer_account = DeveloperAccount(
        user_id=user_id,
        created_at=datetime.utcnow()
    )

    # Add the user to the session
    db.session.add(developer_account)

    # Commit the session to store the developer_account in the database
    db.session.commit()

    developer_account_schema = DeveloperAccountSchema()
    dump = developer_account_schema.dump(developer_account)

    return_val = success_json()
    return_val.update({'developer_account': dump})

    log_info('Developer account created successfully')
    return return_val, 200


@app.route('/api/developer_token/create', methods=['Post'])
@login_required
def create_developer_token():
    current_status = FeatureStatus.unpaid
    json_data = request.get_json()

    # Get the currently logged-in user
    success, user_or_message = get_current_user_info()

    if not success:
        log_error('You must be logged in to create a developer account')
        return jsonify({'status': 'error',
                        'message': 'You must be logged in to create a developer account'}), 401  # We should never hit this

    user = user_or_message
    user_id = user['id']

    # Get the dev account
    developer_account = DeveloperAccount.query.filter_by(user_id=user_id).first()

    if not developer_account.is_enabled:
        log_error('Developer account is not active')
        return jsonify({'status': 'error', 'message': 'Developer account is not active'}), 401

    # Check if the developer account already has 20 tokens
    if len(developer_account.developer_tokens) >= 20:
        log_error('You have reached the maximum limit of 20 tokens')
        return jsonify({'status': 'error', 'message': 'You have reached the maximum limit of 20 tokens'}), 403

    # Get payment account
    payment_account = PaymentAccount.query.filter_by(user_id=user_id).first()

    if developer_account and payment_account:

        user_purchase_statuses = payment_account.user_purchase_statuses

        for user_purchase_status in user_purchase_statuses:
            if user_purchase_status.feature_type == "Developer Subscription":
                log_info('User has a developer subscription')
                if user_purchase_status.feature_status == FeatureStatus.active:
                    current_status = DevTokenStatus.ACTIVE
                else:
                    current_status = DevTokenStatus.INACTIVE
            else:
                log_error('User does not have a developer subscription')
                return jsonify({'status': 'error', 'message': 'This might be a basic subscription'}), 401

        # create a dev token
        developer_token = DeveloperToken(
            title=json_data['title'],
            urls=json_data['urls'],
            status=current_status,
            developer_account_id=developer_account.id,
            created_at=datetime.utcnow()
        )

        # Add the user to the session
        db.session.add(developer_token)

        # Commit the session to store the developer_account in the database
        db.session.commit()

        developer_token_schema = DeveloperTokenSchema()
        dump = developer_token_schema.dump(developer_token)

        return_val = success_json()
        return_val.update({'developer_token': dump})

        log_info('Developer token created successfully')
        return return_val, 200

    # Return 404 if no records are found
    log_error('No developer account associated with user')
    return jsonify({'status': 'error', 'message': 'No developer account associated with user'}), 404


@app.route('/api/tax_foreclosure/create', methods=['POST'])
def create_tax_foreclosure():
    json_data = request.get_json()

    # Get the secret key from the request headers
    key = request.headers.get('X-Secret-Key')

    # Verify the secret key
    if key != secret_key:
        return jsonify({'status': 'error', 'message': 'Invalid secret key'}), 403

    # check if the tax foreclosure already exists
    existing_record = db.session.get(TaxForeclosure, json_data['id'])

    if existing_record:
        # Capture original values before updating
        old_highest_bid = existing_record.highest_bid
        old_status = existing_record.status
        old_data = existing_record.data

        # Clear the existing tags
        existing_record.set_tags([])
        new_tags = []

        # Compare existing record with new data
        has_changes = False
        if existing_record.county != json_data['county']:
            existing_record.county = json_data['county']
            has_changes = True

        # Only check foreclosure_date if it exists in the input data
        if json_data.get('foreclosure_date'):
            new_foreclosure_date = datetime.strptime(json_data['foreclosure_date'], '%Y-%m-%d').date()
            if existing_record.foreclosure_date != new_foreclosure_date:
                existing_record.foreclosure_date = new_foreclosure_date
                has_changes = True

        if json_data.get('upset_bid_date'):
            new_upset_bid_date = datetime.strptime(json_data['upset_bid_date'], '%Y-%m-%d').date()
            if existing_record.upset_bid_date != new_upset_bid_date:
                existing_record.upset_bid_date = new_upset_bid_date
                has_changes = True

        if existing_record.data != json_data['data']:
            existing_record.data = json_data['data']
            new_tags.append('DATA_UPDATED')
            has_changes = True
        if existing_record.status != json_data['status']:
            existing_record.status = json_data['status']
            new_tags.append('STATUS_UPDATED')
            has_changes = True
        if existing_record.highest_bid != json_data['highest_bid']:
            existing_record.highest_bid = json_data['highest_bid']
            new_tags.append('HIGHEST_BID_UPDATED')
            has_changes = True

        # If there are changes, update `date_last_updated` and save the changes
        if has_changes:
            existing_record.date_last_updated = datetime.utcnow().date()  # Update `date_last_updated`

            # Set the updated tags
            existing_record.set_tags(new_tags)

            # Call the history function with the old values and the new updates
            create_tax_foreclosure_history(
                existing_record.id,
                existing_record.case_number,
                old_highest_bid,
                existing_record.highest_bid,  # New highest_bid value
                old_status,
                existing_record.status,  # New status value
                old_data,
                existing_record.data,  # New data value
                existing_record.date_last_updated,
                existing_record.tags
            )

            db.session.commit()
            dump = TaxForeclosureSchema().dump(existing_record)
            return_val = success_json()
            return_val.update({'tax_foreclosure': dump})
            return return_val

        # If no changes, return early
        return {"message": "This entry already exists, we looked for changes... No changes detected."}, 200
    else:
        # If no existing record, create a new one
        foreclosure_date = json_data.get('foreclosure_date', None)
        if foreclosure_date:
            foreclosure_date = datetime.strptime(foreclosure_date, '%Y-%m-%d').date()

        upset_bid_date = json_data.get('upset_bid_date', None)
        if upset_bid_date:
            upset_bid_date = datetime.strptime(upset_bid_date, '%Y-%m-%d').date()

        tax_foreclosure = TaxForeclosure(
            id=json_data['id'],
            case_number=json_data['case_number'],
            parcel_identification=json_data['parcel_identification'],
            reid_number=json_data['reid_number'],
            highest_bid=json_data['highest_bid'],
            status=json_data['status'],
            county=json_data['county'],
            foreclosure_date=foreclosure_date,  # Set foreclosure_date if exists
            upset_bid_date=upset_bid_date,  # Set upset_bid_date if exists
            data=json_data['data'],
            date_last_updated=datetime.now(),
            spider=json_data['spider']
        )

        # Set the initial tag as 'NEW_TAX_FORECLOSURE'
        tax_foreclosure.set_tags(['NEW_TAX_FORECLOSURE'])

        db.session.add(tax_foreclosure)
        db.session.commit()

        dump = TaxForeclosureSchema().dump(tax_foreclosure)
        return_val = success_json()
        return_val.update({'tax_foreclosure': dump})
        return return_val


@app.route('/api/tax_foreclosure/additional_data/create', methods=['POST'])
def create_additional_data():
    json_data = request.get_json()

    # Get the secret key from the request headers
    key = request.headers.get('X-Secret-Key')

    # Verify the secret key
    if key != secret_key:
        return jsonify({'status': 'error', 'message': 'Invalid secret key'}), 403

    # Find the associated tax foreclosure entry
    tax_foreclosure = TaxForeclosure.query.filter_by(id=json_data['tax_foreclosure_id']).first()

    if tax_foreclosure:
        try:
            # Check if additional data already exists
            additional_data = AdditionalTaxForeclosureData.query.filter_by(
                tax_foreclosure_id=json_data['tax_foreclosure_id']).first()

            if additional_data:
                # Update existing data
                additional_data.lot_size = json_data['lot_size']
                additional_data.assessed_value = json_data['assessed_value']
                additional_data.delinquent = json_data['delinquent']
                additional_data.zoning_code = json_data['zoning_code']
                additional_data.has_water = json_data['has_water']
                additional_data.has_electric = json_data['has_electric']
                additional_data.has_sewage = json_data['has_sewage']
                additional_data.legal_description = json_data['legal_description']
                additional_data.structure = json_data['structure']
                additional_data.year_built = json_data['year_built']
                additional_data.condition = json_data['condition']
                additional_data.occupancy = json_data['occupancy']
                additional_data.street = json_data['street']
                additional_data.city = json_data['city']
                additional_data.state = json_data['state']
                additional_data.zip = json_data['zip']
                additional_data.geometry = json_data['geometry']
                additional_data.date_last_updated = datetime.utcnow()

            else:
                # Create new additional data entry
                additional_data = AdditionalTaxForeclosureData(
                    tax_foreclosure_id=json_data['tax_foreclosure_id'],
                    lot_size=json_data['lot_size'],
                    assessed_value=json_data['assessed_value'],
                    delinquent=json_data['delinquent'],
                    zoning_code=json_data['zoning_code'],
                    has_water=json_data['has_water'],
                    has_electric=json_data['has_electric'],
                    has_sewage=json_data['has_sewage'],
                    legal_description=json_data['legal_description'],
                    structure=json_data['structure'],
                    year_built=json_data['year_built'],
                    condition=json_data['condition'],
                    occupancy=json_data['occupancy'],
                    street=json_data['street'],
                    city=json_data['city'],
                    state=json_data['state'],
                    zip=json_data['zip'],
                    geometry=json_data['geometry'],
                    date_last_updated=datetime.utcnow()
                )
                db.session.add(additional_data)

            # Commit changes
            db.session.commit()

            return jsonify({'status': 'success', 'message': 'Additional data created successfully'}), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': str(e)}), 500

    return jsonify({'status': 'error', 'message': 'Tax foreclosure not found'}), 404



@app.route('/api/tax_foreclosure/delete/<tax_foreclosure_id>', methods=['DELETE'])
def delete_tax_foreclosure(tax_foreclosure_id):
    # Get the secret key from the request headers
    key = request.headers.get('X-Secret-Key')

    # Verify the secret key
    if key != secret_key:
        return jsonify({'status': 'error', 'message': 'Invalid secret key'}), 403

    tax_foreclosure = TaxForeclosure.query.filter_by(id=tax_foreclosure_id).first()

    if tax_foreclosure:
        # Delete related additional data first
        AdditionalTaxForeclosureData.query.filter_by(tax_foreclosure_id=tax_foreclosure_id).delete()

        # Now delete the tax_foreclosure record
        db.session.delete(tax_foreclosure)
        db.session.commit()

        return jsonify({'status': 'success', 'message': 'Tax foreclosure deleted successfully'}), 200

    return jsonify({'status': 'error', 'message': 'Tax foreclosure not found'}), 404



@app.route('/api/tax_foreclosure/history', methods=['GET'])
@check_authentication_or_dev_token_required
def get_tax_foreclosure_history():
    # Retrieve all records from the TaxForeclosureHistory table
    foreclosure_history = TaxForeclosureHistory.query.all()

    if foreclosure_history:
        schema = TaxForeclosureHistorySchema(many=True)
        foreclosure_history_list = schema.dump(foreclosure_history)
        return jsonify({'status': 'success', 'foreclosure_history': foreclosure_history_list}), 200

    # Return 404 if no records are found
    return jsonify({'status': 'error', 'message': 'No tax foreclosures history found'}), 404


@app.route('/api/tax_foreclosure/history/<case_number>', methods=['GET'])
@check_authentication_or_dev_token_required
def get_tax_foreclosure_history_by_case_number(case_number):
    log_info(f'Getting tax foreclosure history for case number: {case_number}')
    # Query the database, filtering by the specified case number
    foreclosure_history = TaxForeclosureHistory.query.filter_by(case_number=case_number).all()

    if foreclosure_history:
        # Serialize the list of foreclosure histories
        schema = TaxForeclosureHistorySchema(many=True)
        foreclosure_history_list = schema.dump(foreclosure_history)
        log_info(f'Tax foreclosure history found for case number: {case_number}')
        return jsonify({'status': 'success', 'foreclosure_history': foreclosure_history_list}), 200

    # Return 404 if no records are found
    log_error(f'No tax foreclosure history found for case number: {case_number}')
    return jsonify({'status': 'error', 'message': 'No tax foreclosures were found with this case number'}), 404


@app.route('/api/tax_foreclosure/list', methods=['GET'])
@check_authentication_or_dev_token_required
def list_tax_foreclosures():
    log_info('Listing all tax foreclosures')
    # Retrieve all records from the TaxForeclosure table
    foreclosures = TaxForeclosure.query.all()

    if foreclosures:
        # Serialize the list of foreclosures
        schema = TaxForeclosureSchema(many=True)
        foreclosure_list = schema.dump(foreclosures)
        log_info('Tax foreclosures listed successfully')
        return jsonify({'status': 'success', 'tax_foreclosures': foreclosure_list}), 200

    # Return 404 if no records are found
    log_error('No tax foreclosures found')
    return jsonify({'status': 'error', 'message': 'No tax foreclosures found'}), 404


@app.route('/api/tax_foreclosure/list_by_spider/<spider>', methods=['GET'])
def list_tax_foreclosures_by_spider(spider):
    # Get the secret key from the request headers
    key = request.headers.get('X-Secret-Key')

    # Verify the secret key
    if key != secret_key:
        return jsonify({'status': 'error', 'message': 'Invalid secret key'}), 403

    # Query the database, filtering by the specified spider from the path parameter
    foreclosures = TaxForeclosure.query.filter_by(spider=spider).all()

    if foreclosures:
        # Serialize the list of foreclosures
        schema = TaxForeclosureSchema(many=True)
        foreclosure_list = schema.dump(foreclosures)
        return jsonify({'status': 'success', 'tax_foreclosures': foreclosure_list}), 200

    # Return 404 if no records are found
    return jsonify({'status': 'error', 'message': 'No tax foreclosures found for the specified spider'}), 404


@app.route('/api/tax_foreclosure/list_by_county/<county>', methods=['GET'])
@check_authentication_or_dev_token_required
def list_tax_foreclosures_by_county(county):
    log_info(f'Listing tax foreclosures for county: {county}')
    # Query the database, filtering by the specified county from the path parameter
    foreclosures = TaxForeclosure.query.filter_by(county=county).all()

    if foreclosures:
        # Serialize the list of foreclosures
        schema = TaxForeclosureSchema(many=True)
        foreclosure_list = schema.dump(foreclosures)
        log_info(f'Tax foreclosures found for county: {county}')
        return jsonify({'status': 'success', 'tax_foreclosures': foreclosure_list}), 200

    # Return 404 if no records are found
    log_error(f'No tax foreclosures found for county: {county}')
    return jsonify({'status': 'error', 'message': 'No tax foreclosures found for the specified county'}), 404


@app.route('/api/tax_foreclosure/list_by_status/<status>', methods=['GET'])
@check_authentication_or_dev_token_required
def list_tax_foreclosures_by_status(status):
    log_info(f'Listing tax foreclosures for status: {status}')
    # Query the database, filtering by the specified status from the path parameter
    foreclosures = TaxForeclosure.query.filter_by(status=status).all()

    if foreclosures:
        # Serialize the list of foreclosures
        schema = TaxForeclosureSchema(many=True)
        foreclosure_list = schema.dump(foreclosures)
        log_info(f'Tax foreclosures found for status: {status}')
        return jsonify({'status': 'success', 'tax_foreclosures': foreclosure_list}), 200

    # Return 404 if no records are found
    log_error(f'No tax foreclosures found for status: {status}')
    return jsonify({'status': 'error', 'message': 'No tax foreclosures found for the specified status'}), 404


@app.route('/api/tax_foreclosure/list_by_county_and_status/<county>/<status>', methods=['GET'])
@check_authentication_or_dev_token_required
def list_tax_foreclosures_by_county_and_status(county, status):
    log_info(f'Listing tax foreclosures for county: {county} and status: {status}')
    # Query the database, filtering by the specified county and status
    foreclosures = TaxForeclosure.query.filter_by(county=county, status=status).all()

    if foreclosures:
        # Serialize the list of foreclosures
        schema = TaxForeclosureSchema(many=True)
        foreclosure_list = schema.dump(foreclosures)
        log_info(f'Tax foreclosures found for county: {county} and status: {status}')
        return jsonify({'status': 'success', 'tax_foreclosures': foreclosure_list}), 200

    # Return 404 if no records are found
    log_error(f'No tax foreclosures found for county: {county} and status: {status}')
    return jsonify({'status': 'error', 'message': 'No tax foreclosures found for the specified county and status'}), 404


@app.route('/api/tax_foreclosure/list_by_date/<foreclosure_date>', methods=['GET'])
@check_authentication_or_dev_token_required
def list_tax_foreclosures_by_date(foreclosure_date):
    log_info(f'Listing tax foreclosures for date: {foreclosure_date}')
    try:
        log_info(f'Parsing date: {foreclosure_date}')
        # Parse the date from the path parameter
        date = datetime.strptime(foreclosure_date, '%Y-%m-%d').date()
    except ValueError:
        log_error('Invalid date format. Use YYYY-MM-DD format.')
        return jsonify({'status': 'error', 'message': 'Invalid date format. Use YYYY-MM-DD format.'}), 400

    # Query the database, filtering by the specified foreclosure date
    foreclosures = TaxForeclosure.query.filter_by(foreclosure_date=date).all()

    if foreclosures:
        # Serialize the list of foreclosures
        schema = TaxForeclosureSchema(many=True)
        foreclosure_list = schema.dump(foreclosures)
        log_info(f'Tax foreclosures found for date: {foreclosure_date}')
        return jsonify({'status': 'success', 'tax_foreclosures': foreclosure_list}), 200

    # Return 404 if no records are found
    log_error(f'No tax foreclosures found for date: {foreclosure_date}')
    return jsonify({'status': 'error', 'message': 'No tax foreclosures found for the specified date'}), 404


@app.route('/api/tax_foreclosure/list_before_date/<foreclosure_date>', methods=['GET'])
@check_authentication_or_dev_token_required
def list_tax_foreclosures_before_date(foreclosure_date):
    log_info(f'Listing tax foreclosures before date: {foreclosure_date}')
    try:
        log_info(f'Parsing date: {foreclosure_date}')
        # Parse the date from the path parameter
        date = datetime.strptime(foreclosure_date, '%Y-%m-%d').date()
    except ValueError:
        log_error('Invalid date format. Use YYYY-MM-DD format.')
        return jsonify({'status': 'error', 'message': 'Invalid date format. Use YYYY-MM-DD format.'}), 400

    # Query the database, filtering for records before the specified date
    foreclosures = TaxForeclosure.query.filter(TaxForeclosure.foreclosure_date < date).all()

    if foreclosures:
        # Serialize the list of foreclosures
        schema = TaxForeclosureSchema(many=True)
        foreclosure_list = schema.dump(foreclosures)
        log_info(f'Tax foreclosures found before date: {foreclosure_date}')
        return jsonify({'status': 'success', 'tax_foreclosures': foreclosure_list}), 200

    # Return 404 if no records are found
    log_error(f'No tax foreclosures found before date: {foreclosure_date}')
    return jsonify({'status': 'error', 'message': 'No tax foreclosures found before the specified date'}), 404


@app.route('/api/tax_foreclosure/list_after_date/<foreclosure_date>', methods=['GET'])
@check_authentication_or_dev_token_required
def list_tax_foreclosures_after_date(foreclosure_date):
    log_info(f'Listing tax foreclosures after date: {foreclosure_date}')
    try:
        log_info(f'Parsing date: {foreclosure_date}')
        # Parse the date from the path parameter
        date = datetime.strptime(foreclosure_date, '%Y-%m-%d').date()
    except ValueError:
        log_error('Invalid date format. Use YYYY-MM-DD format.')
        return jsonify({'status': 'error', 'message': 'Invalid date format. Use YYYY-MM-DD format.'}), 400

    # Query the database, filtering for records after the specified date
    foreclosures = TaxForeclosure.query.filter(TaxForeclosure.foreclosure_date > date).all()

    if foreclosures:
        # Serialize the list of foreclosures
        schema = TaxForeclosureSchema(many=True)
        foreclosure_list = schema.dump(foreclosures)
        log_info(f'Tax foreclosures found after date: {foreclosure_date}')
        return jsonify({'status': 'success', 'tax_foreclosures': foreclosure_list}), 200

    # Return 404 if no records are found
    log_error(f'No tax foreclosures found after date: {foreclosure_date}')
    return jsonify({'status': 'error', 'message': 'No tax foreclosures found after specified date'}), 404


@app.route('/api/tax_foreclosure/list_by_case_number/<case_number>', methods=['GET'])
@check_authentication_or_dev_token_required
def get_tax_foreclosure_by_case_number(case_number):
    log_info(f'Getting tax foreclosure for case number: {case_number}')
    # Query the database for a single foreclosure by case number
    foreclosure = TaxForeclosure.query.filter_by(case_number=case_number).first()

    if foreclosure:
        # Serialize the foreclosure record
        schema = TaxForeclosureSchema()
        foreclosure_data = schema.dump(foreclosure)
        log_info(f'Tax foreclosure found for case number: {case_number}')
        return jsonify({'status': 'success', 'foreclosure': foreclosure_data}), 200

    # Return 404 if no record is found
    log_error(f'No tax foreclosure found for case number: {case_number}')
    return jsonify({'status': 'error', 'message': 'No tax foreclosure found for the specified case number'}), 404



@app.route('/api/tax_foreclosure/list_by_county_and_date/<county>/<foreclosure_data>', methods=['GET'])
@check_authentication_or_dev_token_required
def list_tax_foreclosures_by_county_and_date(county, foreclosure_data):
    log_info(f'Getting tax foreclosures for county: {county} and date: {foreclosure_data}')
    # Query the database, filtering by the specified county and date
    foreclosures = TaxForeclosure.query.filter_by(county=county, foreclosure_date=foreclosure_data).all()

    if foreclosures:
        # Serialize the list of foreclosures
        schema = TaxForeclosureSchema(many=True)
        foreclosure_list = schema.dump(foreclosures)
        log_info(f'Tax foreclosures found for county: {county} and date: {foreclosure_data}')
        return jsonify({'status': 'success', 'foreclosure': foreclosure_list}), 200

    # Return 404 if no records are found
    log_error(f'No tax foreclosures found for county: {county} and date: {foreclosure_data}')
    return jsonify({'status': 'error', 'message': 'No tax foreclosures found for the specified county and date'}), 404

    # Once we implement users we will add the other codes...


@app.route('/api/tax_foreclosure/list_by_parcel_or_reid/<parcel_or_reid>', methods=['GET'])
@check_authentication_or_dev_token_required
def list_tax_foreclosures_by_parcel_or_reid(parcel_or_reid):
    log_info(f'Getting tax foreclosures for parcel or reid: {parcel_or_reid}')
    # Query the database, filtering by the specified parcel number or ried
    foreclosures = TaxForeclosure.query.filter_by(parcel_identification=parcel_or_reid).all()
    if foreclosures:
        schema = TaxForeclosureSchema(many=True)
        foreclosure_list = schema.dump(foreclosures)
        log_info(f'Tax foreclosures found for parcel or reid: {parcel_or_reid}')
        return jsonify({'status': 'success', 'foreclosure': foreclosure_list}), 200

    foreclosures = TaxForeclosure.query.filter_by(reid_number=parcel_or_reid).all()
    if foreclosures:
        schema = TaxForeclosureSchema(many=True)
        foreclosure_list = schema.dump(foreclosures)
        log_info(f'Tax foreclosures found for parcel or reid: {parcel_or_reid}')
        return jsonify({'status': 'success', 'foreclosure': foreclosure_list}), 200

    # Return 404 if no records are found
    log_error(f'No tax foreclosures found for parcel or reid: {parcel_or_reid}')
    return jsonify(
        {'status': 'error', 'message': 'No tax foreclosures found for the specified parcel or reid number'}), 404

@app.route('/api/tax_foreclosure/get/foreclosure_id>', methods=['GET'])
@check_authentication_or_dev_token_required
def get_tax_foreclosure_by_id(foreclosure_id):
    """
    Retrieves a single tax foreclosure record by its ID.
    """
    log_info(f'Getting tax foreclosure for ID: {foreclosure_id}')
    # Query the database for a single foreclosure by ID
    foreclosure = TaxForeclosure.query.filter_by(id=foreclosure_id).first()

    if foreclosure:
        schema = TaxForeclosureSchema()
        foreclosure_data = schema.dump(foreclosure)
        log_info(f'Tax foreclosure found for ID: {foreclosure_id}')
        return jsonify({'status': 'success', 'foreclosure': foreclosure_data}), 200

    # Return 404 if no record is found
    log_error(f'No tax foreclosure found for ID: {foreclosure_id}')
    return jsonify(
        {'status': 'error', 'message': 'No tax foreclosure found for the specified ID'}
    ), 404


@app.route('/api/tax_foreclosure/list_by_tag/<tag>', methods=['GET'])
@check_authentication_or_dev_token_required
def list_tax_foreclosures_by_tag(tag):
    log_info(f'Getting tax foreclosures for tag: {tag}')
    # Query the database using the @> operator for JSON array containment
    foreclosures = TaxForeclosure.query.filter(TaxForeclosure.tags.op('@>')(f'"{tag}"')).all()

    if foreclosures:
        # Serialize the list of foreclosures
        schema = TaxForeclosureSchema(many=True)
        foreclosure_list = schema.dump(foreclosures)
        log_info(f'Tax foreclosures found for tag: {tag}')
        return jsonify({'status': 'success', 'foreclosures': foreclosure_list}), 200

    # Return 404 if no records are found
    log_error(f'No tax foreclosures found for tag: {tag}')
    return jsonify({'status': 'error', 'message': 'No tax foreclosures found with this tag'}), 404


@app.route('/api/counties/list', methods=['GET'])
def list_county_codes():
    # Get the secret key from the request headers
    key = request.headers.get('X-Secret-Key')

    # Verify the secret key
    if key != secret_key:
        return jsonify({'status': 'error', 'message': 'Invalid secret key'}), 403

    counties = County.query.all()
    if counties:
        schema = CountySchema(many=True)
        county_list = schema.dump(counties)
        return jsonify({'status': 'success', 'counties': county_list}), 200

    return jsonify({'status': 'error', 'message': 'No counties found'}), 404


@app.route('/api/county/get_by_name/<name>', methods=['GET'])
def get_county_by_name(name):
    # Get the secret key from the request headers
    key = request.headers.get('X-Secret-Key')

    # Verify the secret key
    if key != secret_key:
        return jsonify({'status': 'error', 'message': 'Invalid secret key'}), 403

    county = County.query.filter_by(name=name).all()
    if county:
        schema = CountySchema(many=True)
        county = schema.dump(county)
        return jsonify({'status': 'success', 'county': county}), 200

    return jsonify({'status': 'error', 'message': 'No county found'}), 404


@app.route('/api/stripe/customer/<customer_id>', methods=['GET'])
@login_required
def get_stripe_customer(customer_id):
    """
    Retrieve Stripe customer details by customer_id.
    """
    # Get the currently logged-in user
    success, user_or_message = get_current_user_info()

    user = user_or_message
    user_role = user['role']

    permission = check_permission('/api/stripe/customer', user_role)
    if not permission:
        return jsonify({'status': 'error', 'message': 'You do not have permission to access this resource'}), 403

    try:
        # Call the function to retrieve the customer details
        customer = get_customer(customer_id)
        if customer:
            # Return customer details as JSON
            return jsonify({'status': 'success', 'customer': customer}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Customer not found'}), 404
    except stripe.error.StripeError as e:
        # Handle Stripe errors gracefully
        return jsonify({'status': 'error', 'message': str(e)}), 500
    except Exception as e:
        # Handle general errors
        return jsonify({'status': 'error', 'message': 'An error occurred'}), 500


@app.route('/api/payment_account/create', methods=['POST'])
@login_required
def create_payment_account():
    log_info('Creating a new payment account')
    # Get the currently logged-in user
    success, user_or_message = get_current_user_info()

    user = user_or_message
    user_id = user['id']
    name = user['name']
    email = user['email']

    stripe_customer = create_new_customer(name, email)

    if not stripe_customer:
        log_error('Failed to create a new customer')
        return jsonify({'status': 'error', 'message': 'Failed to create a new customer'}), 401

    payment_account = PaymentAccount(
        user_id=user_id,
        stripe_customer_id=stripe_customer.id,
    )

    db.session.add(payment_account)

    db.session.commit()

    payment_account_schema = PaymentAccountSchema()
    dump = payment_account_schema.dump(payment_account)

    return_val = success_json()
    return_val.update({'payment_account': dump})

    log_info('Payment account created successfully')
    return return_val, 201


@app.route('/api/checkout_session_basic/create', methods=['GET'])
@login_required
def create_checkout_session_basic():
    log_info('Creating a new checkout session for basic subscription')
    # Get the currently logged-in user
    success, user_or_message = get_current_user_info()

    user = user_or_message
    payment_account = user['payment_account']

    # Access the stripe_customer_id from the dictionary
    stripe_customer_id = payment_account['stripe_customer_id']

    checkout = create_stripe_checkout_session_for_basic(stripe_customer_id)

    if not checkout:
        log_error('Failed to create a new checkout session')
        return jsonify({'status': 'error', 'message': 'Failed to create a new checkout session'}), 401

    log_info('Checkout session created successfully')
    return jsonify({'status': 'success', 'checkout': checkout}), 201


@app.route('/api/subscription/switch_to_developer', methods=['POST'])
@login_required
def switch_to_developer_subscription():
    log_info('Switching to developer subscription')
    # Get the currently logged-in user
    success, user_or_message = get_current_user_info()

    user = user_or_message

    payment_account = user['payment_account']
    developer_account = user['developer_account']
    subscription_id = None
    user_purchase_statuses = payment_account['user_purchase_statuses']

    for purchase_status in user_purchase_statuses:
        if purchase_status['feature_type'] == "Basic Subscription" and purchase_status['feature_status'] == 'active':
            subscription_id = purchase_status['id']
            purchase_status['feature_type'] = "Developer Subscription"
            update_user_purchase_status(purchase_status['id'], 'active', purchase_status['feature_type'])

            if developer_account:
                update_developer_account(developer_account['id'], True)

            break
        elif purchase_status['feature_type'] == "Developer Subscription":
            return jsonify({'status': 'error', 'message': 'This user already has a dev subscription, or account '
                                                          'status inactive'}), 404

    upcoming_invoice = switch_to_developer(subscription_id)

    log_info('Switched to developer subscription successfully')
    return jsonify({'status': 'success', 'payment_account': upcoming_invoice}), 200


@app.route('/api/checkout_session_developer/create', methods=['GET'])
@login_required
def create_checkout_session_developer():
    log_info('Creating a new checkout session for developer subscription')
    # Get the currently logged-in user
    success, user_or_message = get_current_user_info()

    user = user_or_message
    payment_account = user['payment_account']

    # Access the stripe_customer_id from the dictionary
    stripe_customer_id = payment_account['stripe_customer_id']

    checkout = create_stripe_checkout_session_for_developer(stripe_customer_id)

    if not checkout:
        log_error('Failed to create a new checkout session')
        return jsonify({'status': 'error', 'message': 'Failed to create a new checkout session'}), 401

    log_info('Checkout session created successfully')
    return jsonify({'status': 'success', 'checkout': checkout}), 201


@app.route('/api/subscription/switch_to_basic', methods=['POST'])
@login_required
def switch_to_basic_subscription():
    log_info('Switching to basic subscription')
    # Get the currently logged-in user
    success, user_or_message = get_current_user_info()

    user = user_or_message

    payment_account = user['payment_account']
    developer_account = user['developer_account']
    subscription_id = None
    user_purchase_statuses = payment_account['user_purchase_statuses']
    developer_tokens = developer_account['developer_tokens']

    for purchase_status in user_purchase_statuses:
        if purchase_status['feature_type'] == "Developer Subscription" and purchase_status[
            'feature_status'] == 'active':
            subscription_id = purchase_status['id']
            purchase_status['feature_type'] = "Basic Subscription"
            update_user_purchase_status(purchase_status['id'], 'active', purchase_status['feature_type'])

            for developer_token in developer_tokens:
                new_status = 'paused'
                update_developer_token(developer_token['id'], new_status)

            update_developer_account(developer_account['id'], False)

            break
        elif purchase_status['feature_type'] == "Basic Subscription":
            return jsonify({'status': 'error', 'message': 'This user already has a dev subscription, or account '
                                                          'status inactive'}), 404

    upcoming_invoice = switch_to_basic(subscription_id)

    log_info('Switched to basic subscription successfully')
    return jsonify({'status': 'success', 'payment_account': upcoming_invoice}), 200


@app.route('/api/subscription/cancel', methods=['POST'])
@login_required
def cancel_user_subscription():
    log_info('Canceling user subscription')
    success, user_or_message = get_current_user_info()
    user = user_or_message
    payment_account = user['payment_account']

    user_purchase_statuses = payment_account['user_purchase_statuses']
    for purchase_status in user_purchase_statuses:
        if purchase_status['feature_type'] == "Developer Subscription" or purchase_status[
            'feature_type'] == "Basic Subscription":
            subscription_id = purchase_status['id']
            canceled_subscription = cancel_subscription(subscription_id)
            delete_user_purchase_status(subscription_id)
            log_info('User subscription canceled successfully')
            return jsonify({'status': 'success', 'payment_account': canceled_subscription}), 200


@app.route('/api/developer_token/update/<developer_token_id>', methods=['POST'])
@login_required
def update_developer_token(developer_token_id):
    log_info('Updating developer token')
    json_data = request.get_json()

    # Get the currently logged-in user
    success, user_or_message = get_current_user_info()

    user = user_or_message

    developer_account = user['developer_account']
    developer_tokens = developer_account['developer_tokens']

    for developer_token in developer_tokens:
        if developer_token['id'] == developer_token_id:

            developer_token_in_database = DeveloperToken.query.filter_by(id=developer_token_id).first()
            if developer_token_in_database is None:
                return jsonify({'status': 'error', 'message': 'Developer Token not found'}), 404

            developer_token_in_database.title = json_data['title']
            developer_token_in_database.urls = json_data['urls']

            db.session.commit()

            developer_token_schema = DeveloperTokenSchema()
            dump = developer_token_schema.dump(developer_token_in_database)

            return_val = success_json()
            return_val.update({'developer_token': dump})

            log_info('Developer token updated successfully')
            return return_val, 200

    log_error('Developer Token not found in')
    return jsonify({'status': 'error', 'message': 'Developer Token not found in'}), 404


@app.route('/api/developer_token/delete/<developer_token_id>', methods=['DELETE'])
@login_required
def delete_developer_token(developer_token_id):
    log_info('Deleting developer token')
    # Get the currently logged-in user
    success, user_or_message = get_current_user_info()

    user = user_or_message

    developer_account = user['developer_account']
    developer_tokens = developer_account['developer_tokens']

    for developer_token in developer_tokens:
        if developer_token['id'] == developer_token_id:

            developer_token_in_database = DeveloperToken.query.filter_by(id=developer_token_id).first()
            if developer_token_in_database is None:
                return jsonify({'status': 'error', 'message': 'Developer Token not found'}), 404

            db.session.delete(developer_token_in_database)

            db.session.commit()

            developer_token_schema = DeveloperTokenSchema()
            dump = developer_token_schema.dump(developer_token_in_database)

            return_val = success_json()
            return_val.update({'developer_token': dump})

            log_info('Developer token deleted successfully')
            return return_val, 200

    log_error('Developer Token not found')
    return jsonify({'status': 'error', 'message': 'Developer Token not found in'}), 404


@app.route('/api/webhook', methods=['POST'])
def webhook():
    event = None
    payload = request.data
    sig_header = request.headers['STRIPE_SIGNATURE']

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        raise e
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        raise e

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        log_info('Checkout session completed')
        session = event['data']['object']

        # Save the customer and subscription IDs to variables
        customer_id = session.get('customer')
        subscription_id = session.get('subscription')

        payment_account = PaymentAccount.query.filter_by(stripe_customer_id=customer_id).first()
        subscription = get_subscription(subscription_id)
        product_id = subscription.plan.product

        if subscription and payment_account and product_id:
            feature_type = get_product(product_id).metadata.get('type')
            feature_status = subscription.status

            # Create a user purchase status
            create_user_purchase_status(subscription_id, payment_account.id, feature_type, feature_status)
    elif event['type'] == 'customer.subscription.updated':
        log_info('Customer subscription updated')
        subscription = event['data']['object']

        customer_id = subscription.get('customer')
        subscription_status = subscription.get('status')

        payment_account = PaymentAccount.query.filter_by(stripe_customer_id=customer_id).first()

        if payment_account and subscription_status:
            developer_account = DeveloperAccount.query.filter_by(user_id=payment_account.user_id).first()
            user_purchase_statuses = payment_account.user_purchase_statuses
            feature_status = subscription_status

            for user_purchase_status in user_purchase_statuses:
                if user_purchase_status.feature_type == "Developer Subscription" or user_purchase_status.feature_type == "Basic Subscription":
                    update_user_purchase_status(user_purchase_status.id, feature_status,
                                                user_purchase_status.feature_type)

                    if developer_account:
                        developer_tokens = developer_account.developer_tokens
                        for developer_token in developer_tokens:
                            update_developer_token(developer_token.id, user_purchase_status.feature_status)

    else:
        print('Unhandled event type {}'.format(event['type']))

    return jsonify(success=True)


if __name__ == "__main__":
    # from models import engine
    app.run(host='localhost', port=5000, debug=False)
