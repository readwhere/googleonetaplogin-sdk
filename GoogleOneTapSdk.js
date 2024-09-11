(function (window) {

    var config = {
        clientId: null,
        enableCookies: false,
        userCookieName: null, 
        onLoginSuccess: null,
        isLoggedIn: false
    };

    let user = null;


    function injectScript(src, async = true, defer = true) {
        if (document.querySelector(`script[src="${src}"]`)) return ;
        
        var script = document.createElement('script');
        script.src = src;
        script.async = async;
        script.defer = defer;
        document.head.appendChild(script);
    }

    // Inject the JOSE library script
    injectScript('https://cdnjs.cloudflare.com/ajax/libs/jose/5.8.0/index.umd.min.js');

    // Inject the Google One Tap library script
    injectScript('https://accounts.google.com/gsi/client');

    // ------------helper functions-----------------
    function checkForLoggedIn() {
        if (config.enableCookies && localStorage.getItem(config.userCookieName)) {
            console.log("Already Logged in");
            config.isLoggedIn = true;
        }
    }

    function checkForInitData() {
        if (!config.clientId) throw new Error('clientId is required');
        if (config.enableCookies && !config.userCookieName) throw new Error('userCookieName is required when cookies are enabled');
    }

    function getLocalStorageItem(name) {
        const encodedData = localStorage.getItem(name);
        if (!encodedData) return null; // Prevents decoding a null value

        try {
            const decodedJsonString = atob(encodedData); // Base64 decode the string
            return JSON.parse(decodedJsonString); // Parse the decoded JSON string
        } catch (e) {
            console.error("Error decoding localStorage data", e);
            return null;
        }
    }

    async function handleCredentialResponse(response) {
        const jwt = response.credential;
      
        if (!jwt) {
            console.error('No credential returned from Google.');
            return;
        }
      
        const decodedToken = decodeJwt(jwt);
        console.log('Decoded Token:', decodedToken);
      
        const isValid = await verifyJwt(jwt);
    
        if (isValid) {
            console.log('Token is valid!');
            
            if (config.enableCookies) {
                const encodedData = btoa(JSON.stringify(decodedToken));
                localStorage.setItem(config.userCookieName, encodedData);
            }
            user = decodedToken;
            config.isLoggedIn = true;

            if (typeof config.onLoginSuccess === 'function') {
                config.onLoginSuccess(user);
            }
        } else {
            console.error('Invalid token!');
        }
    }

    // Decode JWT without verification (header and payload only)
    function decodeJwt(jwt) {
        try {
            const base64Url = jwt.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
            return JSON.parse(jsonPayload);
        } catch (e) {
            console.error("Error decoding JWT:", e);
            return null;
        }
    }

    // Verify the JWT token signature using the Google public keys
    async function verifyJwt(jwt) {
        try {
            const response = await fetch('https://www.googleapis.com/oauth2/v3/certs');
            const { keys } = await response.json();

            // Load the JOSE library for verifying the token
            const { jwtVerify, createRemoteJWKSet } = jose;

            const JWKS = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));

            const { payload } = await jwtVerify(jwt, JWKS, {
                audience: config.clientId,
            });

            console.log('Verified Payload:', payload);
            return true;
        } catch (error) {
            console.error('Token verification failed:', error);
            return false;
        }
    }
 
    // ------------------functions used by user ------------------   
    function initData(_config) {
        if (!_config) throw new Error("_config is required in initData()");

        if (_config.clientId) {
            config.clientId = _config.clientId;
            config.enableCookies = _config.enableCookies || false;

            if (config.enableCookies) {
                if (!_config.userCookieName || _config.userCookieName=='') throw new Error("userCookieName is required when cookies are enabled");
                config.userCookieName = _config.userCookieName;
            }
        } else {
            throw new Error("clientId is required in _config.");
        }
        return true;
    }

    function doLogin(_onSuccess) {
        checkForInitData();
        checkForLoggedIn();

        if (config.isLoggedIn) throw new Error("Already Logged In");

        if (!google || !google.accounts || !google.accounts.id) {
            throw new Error('Google One Tap library is not loaded.');
        }

        config.onLoginSuccess = _onSuccess;

        google.accounts.id.initialize({
            client_id: config.clientId,
            callback: handleCredentialResponse
        });

        google.accounts.id.prompt(); // Automatically prompts the One Tap UI
    }
    
    function doLogout() {
        if (config.enableCookies && getLocalStorageItem(config.userCookieName)) {
            localStorage.removeItem(config.userCookieName);
        }
        user = null;
        config.isLoggedIn = false;
        console.log("Logged Out Successfully.");
        return true;
    }

    function getUserData() {
        if (config.enableCookies) {
            const storedUser = getLocalStorageItem(config.userCookieName);
            if (storedUser) return storedUser;
        } 
        
        if (user) {
            return user;
        }
        
        console.error("No User Found");
        return null;
    }

    // Expose the SDK
    window.GoogleOneTapSdk = {
        initData: initData,
        doLogin: doLogin,
        doLogout: doLogout,
        getUserData: getUserData
    };

})(window);
