// AuthController.js
const AuthService = require('../services/AuthService');
const BcryptPasswordHasher = require('../services/hashing/BcryptPasswordHasher');
const CreateTasks = require('./ControllerTasks');

const authService = new AuthService(new BcryptPasswordHasher());


const AuthController = {
  login: async (req, res) => {
    try {
      const { email, password } = req.body;
      const { token, userId } = await authService.login(email, password);

      CreateTasks.AssociationMessageId(userId);

      return res.status(200).json({ token, userId, message: "Login Bem Sucedido" });
    } catch (error) {
      console.error("Erro durante a autenticação:", error.message);
      return res.status(401).json({ message: error.message });
    }
  }
};

module.exports = AuthController;
    