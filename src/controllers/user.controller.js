import bcrypt from 'bcrypt';
import { ApiError } from '../exceptions/api.error.js';
import { jwtService } from '../services/jwt.service.js';
import { tokenService } from '../services/token.service.js';
import { userService } from '../services/user.service.js';
import { emailService } from '../services/email.service.js';

const getUserProfile = async (req, res) => {
  const { refreshToken } = req.cookies;
  const userData = jwtService.validateRefreshToken(refreshToken);

  if (!userData) {
    throw ApiError.Unauthorized();
  }

  const token = await tokenService.getByToken(refreshToken, 'refreshToken');

  if (!token) {
    throw ApiError.Unauthorized();
  }

  const userId = token.userId;

  const user = await userService.getById(userId);

  if (!user) {
    throw ApiError.NotFound();
  }

  res.json(userService.normalize(user));
};

const updateUserName = async (req, res) => {
  const { name } = req.body;

  if (!name || name.trim() === '') {
    return res.status(400).json({ message: 'Name is required' });
  }

  const userId = req.user.id;

  const updatedUser = await userService.updateUserName(userId, name);

  if (!updatedUser) {
    throw ApiError.NotFound();
  }

  res.json(userService.normalize(updatedUser));
};

const changePassword = async (req, res) => {
  const { oldPassword, newPassword, confirmNewPassword } = req.body;

  if (!oldPassword || !newPassword || !confirmNewPassword) {
    throw ApiError.BadRequest('All fields are required');
  }

  if (newPassword !== confirmNewPassword) {
    throw ApiError.BadRequest('Passwords do not match');
  }

  const userId = req.user.id;

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  await userService.changePassword(userId, hashedPassword);

  res.json({ message: 'Password updated successfully' });
};

const changeEmail = async (req, res) => {
  const { password, newEmail, confirmEmail } = req.body;

  if (!password || !newEmail || !confirmEmail) {
    throw ApiError.BadRequest('All fields are required');
  }

  if (newEmail !== confirmEmail) {
    throw ApiError.BadRequest('Emails do not match');
  }

  const userId = req.user.id;
  const { oldEmail, updatedUser } = await userService.changeEmail(
    userId,
    password,
    newEmail,
  );

  emailService.sendEmailChangeNotification(oldEmail, newEmail);

  res.json({ message: 'Email updated successfully', email: updatedUser.email });
};

export const usersController = {
  getUserProfile,
  updateUserName,
  changePassword,
  changeEmail,
};
