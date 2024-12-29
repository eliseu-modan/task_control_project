const jwt = require("jsonwebtoken");
const config = require("config");
const AuthRepository = require('../repositories/LoginRepository');
const Admin = require("../middlewares/authAdmin");

class AuthService {
  constructor(passwordHasher) {
    this.passwordHasher = passwordHasher;
  }

  async login(email, password) {
    const verifyUser = await AuthRepository.findUserByEmail(email);
    if (!verifyUser) {
      throw new Error("Usuário não encontrado");
    }

    const passwordMatch = await this.passwordHasher.comparePassword(password, verifyUser.password);
    if (!passwordMatch) {
      throw new Error("Senha Incorreta");
    }
    console.log("passwordMatch",passwordMatch)

    const userId = verifyUser.id;

    const userWithAdminInfo = await AuthRepository.findUserById(userId);
    const isAdmin = userWithAdminInfo?.admin || false;
    await Admin.isAdminMiddleware(isAdmin);

    const token = this.generateJwtToken(userId, 300000);

    return { token, userId };
  }

  generateJwtToken(userId, expirationTimeInSeconds) {
    try {
      const secretKey = config.jwtSecret;
      const expirationDate = Math.floor(Date.now() / 1000) + expirationTimeInSeconds;
      const token = jwt.sign({ userId, exp: expirationDate }, secretKey);
      return token;
    } catch (error) {
      console.error("Erro ao gerar o token:", error);
      throw error;
    }
  }
}

module.exports = AuthService;
