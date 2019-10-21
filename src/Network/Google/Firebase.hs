{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.Google.Firebase
  (
    post
  , put
  , loadCredencial
  , defaultEnv
  , runFirebase
  , FirebaseEnv (..)
  , makeCustomToken
  , Scopes
  , get
  , Network.Google.Firebase.delete
  ) where

import           Control.Lens                       ((&), (.~), (?~), (^.),
                                                     (^?))
import           Control.Monad.Catch
import           Control.Monad.IO.Class
import           Control.Monad.Reader
import           Control.Monad.Trans.Except
import           Crypto.JWT
import           Data.Aeson
import           Data.ByteString.Lazy               (ByteString)
import qualified Data.ByteString.Lazy               as LBS
import qualified Data.HashMap.Strict                as HM
import           Data.Scientific
import           Data.Time.Clock
import           Data.Typeable
import qualified Network.Google                     as G
import qualified Network.Google.Auth                as G
import qualified Network.Google.Auth.ServiceAccount as G
import           Network.HTTP.Client                (newManager)
import           Network.HTTP.Conduit               hiding (path)
import           System.IO                          (stdout)

type Scopes = '["https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/firebase.database"]
data FirebaseEnv = FirebaseEnv
  { env       :: G.Env Scopes
  , projectId :: String
  }
-- type Firebase = Reader FirebaseEnv

runFirebase = flip runReaderT

freq :: (MonadReader FirebaseEnv m, MonadIO m, MonadCatch m) => Request -> m ByteString
freq req = do
  env' <- asks env
  req' <- liftIO $ G.authorize req (env' ^. G.envStore) (env' ^. G.envLogger) (env' ^. G.envManager)
  responseBody <$> httpLbs req' (env' ^. G.envManager)

get :: (MonadReader FirebaseEnv m, MonadIO m, MonadCatch m) => String -> Bool -> m Object
get path shallow = do
  pid <- asks projectId
  let url = "https://" ++ pid ++ ".firebaseio.com/" ++ path ++ ".json"
  let qs = [("print", Just "pretty")
           , ("shallow", Just $ boolStr shallow)
           ]
  initialRequest <- liftIO $ parseRequest url
  let req = setQueryString qs $ initialRequest { method = "GET" }
  r <- decode <$> freq req
  maybe (throwM UnexpectedResponseFormat) return r

boolStr True  = "true"
boolStr False = "false"

post :: (MonadReader FirebaseEnv m, MonadIO m, ToJSON a, MonadCatch m) => String -> a -> m ByteString
post path val = do
  pid <- asks projectId
  let url = "https://" ++ pid ++ ".firebaseio.com/" ++ path ++ ".json"
  initialRequest <- liftIO $ parseRequest url
  let req = initialRequest { method = "POST", requestBody = RequestBodyLBS $ encode val }
  freq req

put :: (MonadReader FirebaseEnv m, MonadIO m, ToJSON a, MonadCatch m) => String -> a -> m ByteString
put path val = do
  pid <- asks projectId
  let url = "https://" ++ pid ++ ".firebaseio.com/" ++ path ++ ".json"
  initialRequest <- liftIO $ parseRequest url
  let req = initialRequest { method = "PUT", requestBody = RequestBodyLBS $ encode val }
  freq req

delete :: (MonadReader FirebaseEnv m, MonadIO m, MonadCatch m) => String -> m ByteString
delete path = do
  pid <- asks projectId
  let url = "https://" ++ pid ++ ".firebaseio.com/" ++ path ++ ".json"
  initialRequest <- liftIO $ parseRequest url
  let req = initialRequest { method = "DELETE" }
  freq req

data Cred = Cred
  { credProjectId :: String
  }

instance FromJSON Cred where
  parseJSON = withObject "Cred" $ \v -> Cred <$> v .: "project_id"

loadCredencial :: FilePath -> IO (G.Credentials Scopes, String)
loadCredencial path = do
  c <- G.fromFilePath path :: IO (G.Credentials Scopes)
  Just c' <- decode <$> LBS.readFile path :: IO (Maybe Cred)
  return (c, credProjectId c')

defaultEnv :: (G.Credentials Scopes, String) -> IO FirebaseEnv
defaultEnv (cred, pid) = do
  mgr <- newManager G.tlsManagerSettings
  lgr <- G.newLogger G.Error stdout
  genv <- G.newEnvWith cred lgr mgr
  return $ FirebaseEnv genv pid

mkClaims email uid = do
  t <- getCurrentTime
  let audUrl = "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
  pure $ emptyClaimsSet
    & claimIss ?~ email
    & claimSub ?~ email
    & claimAud ?~ Audience [audUrl]
    & claimExp ?~ NumericDate (addUTCTime (60*60) t)
    & claimIat ?~ NumericDate t
    & Crypto.JWT.unregisteredClaims .~ HM.fromList [("uid", Number uid)]

doJwtSign :: JWK -> ClaimsSet -> IO (Either JWTError SignedJWT)
doJwtSign jwk' claims = runExceptT $ do
  alg' <- bestJWSAlg jwk'
  let h = newJWSHeader ((), alg') & Crypto.JWT.typ ?~ HeaderParam () "JWT"
  signClaims jwk' h claims

makeCustomToken :: (MonadReader FirebaseEnv m, MonadIO m, MonadThrow m) => Scientific -> m ByteString
makeCustomToken uid = do
  env' <- asks env
  liftIO $ do
    cred <- G.retrieveAuthFromStore $ env' ^. G.envStore
    (email, privateKey) <- case G._credentials cred of
                    G.FromAccount sa -> return $ (G.getServiceEmail sa, G.getServicePrivateKey sa)
                    _ -> throwM BadCredencial
    let jwk' = fromRSA privateKey
    emailString <- maybe (throwM BadCredencial) return $  email ^? stringOrUri
    claims <- mkClaims emailString uid
    jwt <- doJwtSign jwk' claims >>= either (throwM . SignJWTException) return
    return $ encodeCompact jwt

data FirebaseException =
  BadCredencial
  | SignJWTException JWTError
  | UnexpectedResponseFormat
  deriving(Show, Typeable)
instance Exception FirebaseException
