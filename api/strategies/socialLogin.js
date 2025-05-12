const { createSocialUser, handleExistingUser } = require('./process');
const { isEnabled } = require('~/server/utils');
const { findUser } = require('~/models');
const { logger } = require('~/config');

const socialLogin =
  (provider, getProfileDetails) => async (accessToken, refreshToken, idToken, profile, cb) => {
    console.time(`[OAuth] ${provider}`);
    logger.info(`🔁 ${provider} callback received`);
    logger.info(`🔐 Access Token: ${accessToken}`);
    logger.info(`📧 Email: ${profile?.emails?.[0]?.value}`);

    try {
      const {
        email,
        id,
        avatarUrl,
        username,
        name,
        emailVerified,
      } = getProfileDetails({ idToken, profile });

      logger.info(`📦 Mapped Profile: ${JSON.stringify({ email, id, username, name })}`);

      const oldUser = await findUser({ email: email.trim() });
      const ALLOW_SOCIAL_REGISTRATION = isEnabled(process.env.ALLOW_SOCIAL_REGISTRATION);

      if (oldUser) {
        logger.info(`👤 Found existing user: ${oldUser.id}`);
        await handleExistingUser(oldUser, avatarUrl);
        console.timeEnd(`[OAuth] ${provider}`);
        return cb(null, oldUser);
      }

      if (ALLOW_SOCIAL_REGISTRATION) {
        logger.info(`🆕 Creating new user via social login`);
        const newUser = await createSocialUser({
          email,
          avatarUrl,
          provider,
          providerKey: `${provider}Id`,
          providerId: id,
          username,
          name,
          emailVerified,
        });
        logger.info(`✅ Created new user: ${newUser.id}`);
        console.timeEnd(`[OAuth] ${provider}`);
        return cb(null, newUser);
      }

      logger.warn(`🚫 Social registration is disabled for new users`);
      console.timeEnd(`[OAuth] ${provider}`);
      return cb(null, false);
    } catch (err) {
      logger.error(`❌ [${provider}Login]`, err);
      console.timeEnd(`[OAuth] ${provider}`);
      return cb(err);
    }
  };

module.exports = socialLogin;
