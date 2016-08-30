<?php
use OC\Encryption\CalCrypt;
use OCP\IDBConnection;

/**
 * ownCloud - user_saml
 *
 * @author    Sixto Martin <smartin@yaco.es>
 * @copyright 2012 Yaco Sistemas // CONFIA
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
class OC_USER_SAML extends OC_User_Backend
{

    /**
     * Whether or not to force login by SAML
     *
     * @var string
     */
    public $forceLogin;
    /**
     * Whether or not to auto-create an Owncloud user
     *
     * @var string
     */
    public $autocreate;
    /**
     * Whether or not to update user data upon login
     *
     * @var string
     */
    public $updateUserData;
    /**
     * Whether or not groups are protected
     *
     * @var array
     */
    public $protectedGroups;
    /**
     * The default group to give a SAML user
     *
     * @var string
     */
    public $defaultGroup;
    /**
     * The field that maps to the username
     *
     * @var array
     */
    public $usernameMapping;
    /**
     * The field that maps to the email address
     *
     * @var array
     */
    public $mailMapping;
    /**
     * The field that maps to the display name
     *
     * @var array
     */
    public $displayNameMapping;
    /**
     * The field that maps to your total quota
     *
     * @var array
     */
    public $quotaMapping;
    /**
     * Default quota for new users
     *
     * @var string
     */
    public $defaultQuota;
    /**
     * The field that determines what group the user is in
     *
     * @var array
     */
    public $groupMapping;
    /**
     * Auth object
     *
     * @var SimpleSAML_Auth_Simple
     */
    public $auth;
    /**
     * Path to SimpleSAML
     *
     * @var string
     */
    protected $sspPath;
    /**
     * Service provider source
     *
     * @var string
     */
    protected $spSource;
    /**
     * Database connection
     *
     * @var IDBConnection
     */
    protected $db;

    /**
     * OC_USER_SAML constructor.
     */
    public function __construct()
    {
        $this->sspPath            = \OC::$server->getConfig()->getAppValue('user_saml', 'saml_ssp_path', '');
        $this->spSource           = \OC::$server->getConfig()->getAppValue('user_saml', 'saml_sp_source', '');
        $this->forceLogin         = \OC::$server->getConfig()->getAppValue('user_saml', 'saml_force_saml_login', false);
        $this->autocreate         = \OC::$server->getConfig()->getAppValue('user_saml', 'saml_autocreate', false);
        $this->updateUserData     = \OC::$server->getConfig()->getAppValue('user_saml', 'saml_update_user_data', false);
        $this->defaultGroup       = \OC::$server->getConfig()->getAppValue('user_saml', 'saml_default_group', '');
        $this->protectedGroups    = explode(',', preg_replace('/\s+/', '', \OC::$server->getConfig()->getAppValue('user_saml', 'saml_protected_groups', '')));
        $this->usernameMapping    = explode(',', preg_replace('/\s+/', '', \OC::$server->getConfig()->getAppValue('user_saml', 'saml_username_mapping', '')));
        $this->mailMapping        = explode(',', preg_replace('/\s+/', '', \OC::$server->getConfig()->getAppValue('user_saml', 'saml_email_mapping', '')));
        $this->displayNameMapping = explode(',', preg_replace('/\s+/', '', \OC::$server->getConfig()->getAppValue('user_saml', 'saml_displayname_mapping', '')));
        $this->quotaMapping       = explode(',', preg_replace('/\s+/', '', \OC::$server->getConfig()->getAppValue('user_saml', 'saml_quota_mapping', '')));
        $this->defaultQuota       = \OC::$server->getConfig()->getAppValue('user_saml', 'saml_default_quota', '');
        $this->groupMapping       = explode(',', preg_replace('/\s+/', '', \OC::$server->getConfig()->getAppValue('user_saml', 'saml_group_mapping', '')));

        if (!empty($this->sspPath) && !empty($this->spSource)) {
            include_once $this->sspPath . '/lib/_autoload.php';

            $this->auth = new SimpleSAML_Auth_Simple($this->spSource);

            if (isset($_COOKIE['user_saml_logged_in']) AND $_COOKIE['user_saml_logged_in'] AND !$this->auth->isAuthenticated()) {
                unset($_COOKIE['user_saml_logged_in']);
                setcookie('user_saml_logged_in', null, -1);
                \OC::$server->getUserSession()->logout();
            }
        }
    }

    /**
     * Determines if a user if a user was created or not
     *
     * @return bool
     * @throws \Exception
     */
    public function checkPassword()
    {
        if (!$this->auth->isAuthenticated()) {
            return false;
        }

        $attributes = $this->auth->getAttributes();

        foreach ($this->usernameMapping as $usernameMapping) {
            if (array_key_exists($usernameMapping, $attributes) && !empty($attributes[$usernameMapping][0])) {
                $uid = $attributes[$usernameMapping][0];
                OCP\Util::writeLog('saml', 'Authenticated user ' . $uid, OCP\Util::DEBUG);
                if ($this->autocreate && !\OC::$server->getUserManager()->userExists($uid)) {
                    return $this->createUser($uid);
                }

                return $uid;
            }
        }

        OCP\Util::writeLog('saml', 'Not found attribute used to get the username at the requested saml attribute assertion', OCP\Util::DEBUG);
        $secure_cookie = OC_Config::getValue('forcessl', false);
        $expires       = time() + OC_Config::getValue('remember_login_cookie_lifetime', 60 * 60 * 24 * 15);
        setcookie('user_saml_logged_in', '1', $expires, '', '', $secure_cookie);

        return false;
    }

    /**
     * Creates the Owncloud user
     *
     * @param $uid
     *
     * @return bool
     * @throws Exception
     */
    public function createUser($uid)
    {
        if (preg_match('/[^a-zA-Z0-9 _\.@\-]/', $uid)) {
            OCP\Util::writeLog('saml', 'Invalid username "' . $uid . '", allowed chars "a-zA-Z0-9" and "_.@-" ', OCP\Util::DEBUG);

            return false;
        } else {
            // Do we want to save the unhashed, encrypted password?
            if (\OC::$server->getConfig()->getAppValue('user_saml', 'save_encrypted_pw', false)) {
                $random_password = md5(random_bytes(64));
                $this->saveEncryptedPassword($uid, $random_password);
            } else {
                $random_password = random_bytes(64);
            }

            OCP\Util::writeLog('saml', 'Creating new user: ' . $uid, OCP\Util::DEBUG);
            \OC::$server->getUserManager()->createUser($uid, $random_password);

            return $uid;
        }
    }

    /**
     * Saves the password in an AES_ENCRYPT with the configured encrypt_key for retrieval (AES_DECRYPT) later.  Used to
     * display if a user needs to use 3rd-party plugin but is a SAML user
     *
     * @param $uuid
     * @param $password
     *
     * @throws \UnexpectedValueException
     */
    private function saveEncryptedPassword($uuid, $password)
    {
        $db    = $this->getDb();
        $query = $db->getQueryBuilder();

        $calcrypt = new CalCrypt($query);
        $calcrypt->insertEncrypted([
            'uuid'     => $uuid,
            'password' => $password
        ]);

        $query->insert('user_api')->execute();
    }

    /**
     * Returns the database connection
     *
     * @return IDBConnection
     */
    public function getDb()
    {
        if (null === $this->db) {
            $this->setDb(\OC::$server->getDatabaseConnection());
        }

        return $this->db;
    }

    /**
     * Sets the database connection
     *
     * @param IDBConnection $db
     */
    public function setDb($db)
    {
        $this->db = $db;
    }
}
