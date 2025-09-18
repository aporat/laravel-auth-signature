<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Timestamp Tolerance
    |--------------------------------------------------------------------------
    |
    | Defines the time window, in seconds, for which a signature is considered
    | valid. A request with a timestamp outside this window (before or after
    | the current server time) will be rejected. This helps prevent replay
    | attacks. The default is 300 seconds (5 minutes).
    |
    */
    'timestamp_tolerance_seconds' => 300,

    /*
    |--------------------------------------------------------------------------
    | Client Definitions
    |--------------------------------------------------------------------------
    |
    | This is where you define each client that is allowed to make signed
    | requests to your API. The key of each entry is the Client ID that
    | will be sent in the `X-Auth-Client-ID` header.
    |
    */
    'clients' => [

        'your_client_id_here' => [
            // The secret key used to sign requests for this client.
            // This should be a long, random, and unique string.
            'client_secret' => env('CLIENT_SECRET_KEY', 'your_super_secret_key_here'),

            // The bundle ID or unique identifier for the client application.
            'bundle_id' => 'com.yourcompany.yourapp',

            // (Optional) The minimum authentication version this client must use.
            // Requests with an `X-Auth-Version` header below this value will be rejected.
            'min_auth_level' => 300,
        ],

        'another_client_id' => [
            'client_secret' => env('ANOTHER_CLIENT_SECRET'),
            'bundle_id' => 'com.yourcompany.anotherapp',
            'min_auth_level' => 400,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Version Definitions
    |--------------------------------------------------------------------------
    |
    | This array defines the rules for different signature versions. This allows
    | you to change the signature algorithm over time without breaking older
    | clients. The key is the version number sent in the `X-Auth-Version` header.
    |
    */
    'auth_versions' => [

        // A basic version with no special settings. It will use the default
        // signature template.
        300 => [],

        // A more advanced version with custom settings.
        400 => [
            // (Optional) A version-specific secret that is appended to the
            // client's main secret. Useful for rotating secrets.
            'secret' => 'version_400_specific_secret',

            // (Optional) A static string included in the signature.
            'state' => 'some_static_state_string_for_v400',

            // (Optional) A custom template defining the exact order and
            // components of the string-to-be-signed. If omitted, a
            // default order is used.
            'signature_template' => [
                'method',
                'path',
                'timestamp',
                'client_id',
                'auth_version',
                'bundle_id',
                'state',
                'signature', // This represents the canonicalized parameters
            ],
        ],
    ],

];
