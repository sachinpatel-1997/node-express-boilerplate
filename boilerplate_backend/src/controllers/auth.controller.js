const httpStatus = require('http-status');
const catchAsync = require('../utils/catchAsync');
const { authService, userService, tokenService, emailService } = require('../services');
const { OAuth2Client } = require('google-auth-library');
const { User } = require('../models');
const config = require('../config/config');

const client = new OAuth2Client(config.clientId);

const googleSignin = catchAsync(async (req, res) => {
  const { tokenId } = req.body;

  // console.log('tokenId ------> ', tokenId);

  client
    .verifyIdToken({
      idToken: tokenId,
      audience: config.clientId,
    })
    .then((response) => {
      const { email_verified, name, email } = response.payload;

      if (email_verified) {
        User.findOne({ email }).exec(async (err, user) => {
          if (err) {
            return res.status(400).json({
              error: 'somthing went wrong',
            });
          } else {
            if (user) {
              console.log('-------------- >   login');
              console.log('user --> ', user);
              const tokens = await tokenService.generateAuthTokens(user);
              res.send({ user, tokens });
            } else {
              console.log('-------------- >   register');
              const body = {
                name: name,
                email: email,
                password: ``,
                role: 'user',
                isGoogleSignin: true,
              };
              const currUser = await userService.createUser(body);
              console.log(body);
              const tokens = await tokenService.generateAuthTokens(currUser);
              res.status(httpStatus.CREATED).send({ user: currUser, tokens });
            }
          }
        });
      }

      // console.log(response.payload);
    });
});

const register = catchAsync(async (req, res) => {
  const user = await userService.createUser(req.body);
  const tokens = await tokenService.generateAuthTokens(user);
  res.status(httpStatus.CREATED).send({ user, tokens });
});

const login = catchAsync(async (req, res) => {
  const { email, password } = req.body;
  const user = await authService.loginUserWithEmailAndPassword(email, password);
  const tokens = await tokenService.generateAuthTokens(user);
  res.send({ user, tokens });
});

const logout = catchAsync(async (req, res) => {
  await authService.logout(req.body.refreshToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const refreshTokens = catchAsync(async (req, res) => {
  const tokens = await authService.refreshAuth(req.body.refreshToken);
  res.send({ ...tokens });
});

const forgotPassword = catchAsync(async (req, res) => {
  const resetPasswordToken = await tokenService.generateResetPasswordToken(req.body.email);
  await emailService.sendResetPasswordEmail(req.body.email, resetPasswordToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const resetPassword = catchAsync(async (req, res) => {
  await authService.resetPassword(req.query.token, req.body.password);
  res.status(httpStatus.NO_CONTENT).send();
});

const sendVerificationEmail = catchAsync(async (req, res) => {
  const verifyEmailToken = await tokenService.generateVerifyEmailToken(req.user);
  await emailService.sendVerificationEmail(req.user.email, verifyEmailToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const verifyEmail = catchAsync(async (req, res) => {
  await authService.verifyEmail(req.query.token);
  res.status(httpStatus.NO_CONTENT).send();
});

module.exports = {
  googleSignin,
  register,
  login,
  logout,
  refreshTokens,
  forgotPassword,
  resetPassword,
  sendVerificationEmail,
  verifyEmail,
};
