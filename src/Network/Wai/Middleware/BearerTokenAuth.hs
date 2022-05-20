{-# LANGUAGE OverloadedStrings #-}

-- | Implements HTTP Bearer Token Authentication.
--
-- This module is based on 'Network.Wai.Middleware.HttpAuth'.

module Network.Wai.Middleware.BearerTokenAuth
  ( tokenAuth
  , tokenAuth'
  , tokenListAuth
  , CheckToken
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as S
import Data.Word8 (isSpace, toLower)
import Network.HTTP.Types (hAuthorization, hContentType, status401)
import Network.Wai (Middleware, Request(requestHeaders), Response, responseLBS)

-- | Check if a given token is valid.
type CheckToken = ByteString -> IO Bool

-- | Perform token authentication.
--
-- If the token is accepted, leave the Application unchanged.
-- Otherwise, send a @401 Unauthorized@ HTTP response.
--
-- > tokenAuth (\tok -> return $ tok == "abcd" )
tokenAuth :: CheckToken -> Middleware
tokenAuth checker = tokenAuth' (const checker)

-- | Like 'tokenAuth', but also passes a request to the authentication function.
--
tokenAuth' :: (Request -> CheckToken) -> Middleware
tokenAuth' checkByReq app req sendRes = do
  let checker = checkByReq req
  let pass = app req sendRes
  authorized <- check checker req
  if authorized
    then pass -- Pass the Application on successful auth
    else sendRes rspUnauthorized -- Send a @401 Unauthorized@ response on failed auth

-- | Perform token authentication
-- based on a list of allowed tokens.
--
-- > tokenListAuth ["secret1", "secret2"]
tokenListAuth :: [ByteString] -> Middleware
tokenListAuth tokens = tokenAuth (\tok -> return $ tok `elem` tokens)

check :: CheckToken -> Request -> IO Bool
check checkCreds req =
  case extractBearerFromRequest req of
    Nothing -> return False
    Just token -> checkCreds token

rspUnauthorized :: Response
rspUnauthorized =
  responseLBS
    status401
    [(hContentType, "text/plain"), ("WWW-Authenticate", "Bearer")]
    "Bearer token authentication is required"

extractBearerFromRequest :: Request -> Maybe ByteString
extractBearerFromRequest req = do
  authHeader <- lookup hAuthorization (requestHeaders req)
  extractBearerAuth authHeader

-- | Extract bearer authentication data from __Authorization__ header
-- value. Returns bearer token
--
-- Source: https://hackage.haskell.org/package/wai-extra-3.1.11/docs/Network-Wai-Middleware-HttpAuth.html
extractBearerAuth :: ByteString -> Maybe ByteString
extractBearerAuth bs =
  let (x, y) = S.break isSpace bs
   in if S.map toLower x == "bearer"
        then Just $ S.dropWhile isSpace y
        else Nothing
