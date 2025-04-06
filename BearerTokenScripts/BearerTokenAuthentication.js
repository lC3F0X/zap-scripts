/*
 * Authentication script for ZAP to retrieve Bearer and Refresh tokens
 * Author: Ice Fox
 * Date: 2025-04-01
 * Version: 1.3
 */

const ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
const HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
const URI = Java.type("org.apache.commons.httpclient.URI");
const HttpRequestHeader = Java.type(
	"org.parosproxy.paros.network.HttpRequestHeader"
);

// Main authentication function
function authenticate(helper, paramsValues, credentials) {
	print("🚀 [Authentication] Script starting...\n");

	// ✅ Token reuse validation
	const existingToken = ScriptVars.getGlobalVar("accessToken");
	if (existingToken) {
		print("🔒 Access token already set. Skipping authentication.\n");
		return null;
	}

	const loginUrl = paramsValues.get("loginUrl");
	const tokenAccessor = paramsValues.get("tokenAccessor") ?? "access_token";
	const refreshTokenAccessor =
		paramsValues.get("refreshTokenAccessor") ?? "refresh_token";

	const usernameAccessor = paramsValues.get("usernameAccessor") ?? "username";
	const passwordAccessor = paramsValues.get("passwordAccessor") ?? "password";

	const username = credentials.getParam("username");
	const password = credentials.getParam("password");

	// Handle missing username/password gracefully
	if (!username || !password) {
		const missingField = !username ? "username" : "password";
		throw new Error(
			`❌ Authentication failed: Missing credential "${missingField}". Please verify your credentials configuration.`
		);
	}

	print(`🔑 Authenticating user: ${username}\n`);
	print(`🌐 Login endpoint: ${loginUrl}\n`);

	// Set global variables
	ScriptVars.setGlobalVar("tokenAccessor", tokenAccessor);
	ScriptVars.setGlobalVar("refreshUrl", paramsValues.get("refreshUrl"));
	ScriptVars.setGlobalVar("refreshTokenAccessor", refreshTokenAccessor);

	const loginUri = new URI(loginUrl, false);
	const loginMsg = helper.prepareMessage();

	// Prepare login request body
	const requestBody = JSON.stringify({
		[usernameAccessor]: username,
		[passwordAccessor]: password,
	});

	loginMsg.setRequestHeader(
		new org.parosproxy.paros.network.HttpRequestHeader(
			HttpRequestHeader.POST,
			loginUri,
			HttpHeader.HTTP11
		)
	);
	loginMsg
		.getRequestHeader()
		.setHeader(HttpHeader.CONTENT_TYPE, "application/json");
	loginMsg.setRequestBody(requestBody);
	loginMsg
		.getRequestHeader()
		.setContentLength(loginMsg.getRequestBody().length());

	print("📤 Sending authentication request...\n");

	try {
		helper.sendAndReceive(loginMsg, false);
	} catch (error) {
		print("❌ Error sending authentication request: " + error.message + "\n");
		throw error;
	}

	const statusCode = loginMsg.getResponseHeader().getStatusCode();
	print(`📨 Authentication response received, Status: ${statusCode}\n`);

	if (statusCode !== 200) {
		throw new Error(`❌ Authentication failed with status code: ${statusCode}`);
	}

	const responseBody = JSON.parse(loginMsg.getResponseBody().toString());
	const accessToken = responseBody[tokenAccessor];
	const refreshToken = responseBody[refreshTokenAccessor];

	if (!accessToken) {
		throw new Error("❌ Authentication response missing access token.");
	}

	ScriptVars.setGlobalVar("accessToken", accessToken);
	print("🔑 Access token obtained successfully.\n");

	if (refreshToken) {
		ScriptVars.setGlobalVar("refreshToken", refreshToken);
		print("♻️ Refresh token received and stored.\n");
	} else {
		print("⚠️ No refresh token received from authentication response.\n");
	}

	print("✅ Authentication completed successfully.\n");
	return loginMsg;
}

// Required parameters
function getRequiredParamsNames() {
	return ["loginUrl"];
}

// Optional parameters
function getOptionalParamsNames() {
	return [
		"tokenAccessor",
		"refreshUrl",
		"refreshTokenAccessor",
		"usernameAccessor",
		"passwordAccessor",
	];
}

// Credential parameters
function getCredentialsParamsNames() {
	return ["username", "password"];
}
