const AuthService = require('../../services/AuthService');
const AuthRepository = require('../../repositories/LoginRepository');
const Admin = require('../../middlewares/authAdmin');
const jwt = require('jsonwebtoken');

jest.mock('../../repositories/LoginRepository');
jest.mock('../../middlewares/authAdmin');
jest.mock('jsonwebtoken');


describe('AuthService', () => {
  let authService;
  let passwordHasher;

  beforeEach(() => {
    // Mock para o passwordHasher
    passwordHasher = {
      comparePassword: jest.fn(),
    };

    // Instância do AuthService com o mock do passwordHasher
    authService = new AuthService(passwordHasher);
  });

  it('should return a token and userId on successful login', async () => {
    const mockUser = { id: 1, password: 'hashedPassword' };
    const mockToken = 'fake-jwt-token';

    // Mock dos métodos do AuthRepository
    AuthRepository.findUserByEmail.mockResolvedValue(mockUser);
    AuthRepository.findUserById.mockResolvedValue({ admin: true });

    // Mock do passwordHasher
    passwordHasher.comparePassword.mockResolvedValue(true);

    // Mock do JWT
    jwt.sign.mockReturnValue(mockToken);

    // Mock de isAdminMiddleware
    Admin.isAdminMiddleware.mockResolvedValue(true);

    // Dados de entrada para a função login
    const email = 'test@example.com';
    const password = 'password123';

    // Chamada da função login
    const result = await authService.login(email, password);

    // Verificações
    expect(AuthRepository.findUserByEmail).toHaveBeenCalledWith(email);
    expect(passwordHasher.comparePassword).toHaveBeenCalledWith(password, mockUser.password);
    expect(Admin.isAdminMiddleware).toHaveBeenCalledWith(true);
    expect(result).toEqual({ token: mockToken, userId: mockUser.id });
  });

  it('should throw an error if user is not found', async () => {
    AuthRepository.findUserByEmail.mockResolvedValue(null);

    const email = 'test@example.com';
    const password = 'password123';

    await expect(authService.login(email, password)).rejects.toThrow('Usuário não encontrado');
  });

  it('should throw an error if password is incorrect', async () => {
    const mockUser = { id: 1, password: 'hashedPassword' };

    AuthRepository.findUserByEmail.mockResolvedValue(mockUser);
    passwordHasher.comparePassword.mockResolvedValue(false);

    const email = 'test@example.com';
    const password = 'wrongPassword';

    await expect(authService.login(email, password)).rejects.toThrow('Senha Incorreta');
  });

  it('should throw an error if jwt token generation fails', async () => {
    const mockUser = { id: 1, password: 'hashedPassword' };

    AuthRepository.findUserByEmail.mockResolvedValue(mockUser);
    passwordHasher.comparePassword.mockResolvedValue(true);
    AuthRepository.findUserById.mockResolvedValue({ admin: true });

    jwt.sign.mockImplementation(() => {
      throw new Error('Erro ao gerar o token');
    });

    const email = 'test@example.com';
    const password = 'password123';

    await expect(authService.login(email, password)).rejects.toThrow('Erro ao gerar o token');
  });
});
