import express from "express";
import "dotenv/config";
import { v4 as uuidv4 } from "uuid";
import * as bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import users from "./database";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

const verifyEmailAvailabilityMiddleware = (request, response, next) => {
  const { email } = request.body;

  const userAlreadyExists = users.find((element) => element.email === email);

  if (userAlreadyExists) {
    return response
      .status(409)
      .json({ message: "This email is already being used." });
  }

  next();
};

const verifyAuthToken = (request, response, next) => {
  let token = request.headers.authorization;

  if (!token) {
    return response
      .status(401)
      .json({ message: "Missing authorization token" });
  }

  token = token.split(" ")[1];

  jwt.verify(token, "SECRET_KEY", (error, decoded) => {
    if (error) {
      return response.status(401).json({ message: "Invalid token" });
    }
    request.userId = decoded.id;
    request.userEmail = decoded.email;
    request.isAdm = decoded.isAdm;
    next();
  });
};

const verifyIsAdmMiddleware = (request, response, next) => {
  const idParams = request.params.id;

  if (request.isAdm === true) {
    next();
  } else if (idParams === request.userId) {
    next();
  } else {
    return response.status(403).json({
      message: "You must be the account owner or adm to update this account.",
    });
  }
};

const createUserService = async (name, email, password, isAdm) => {
  const dateNow = new Date();
  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    name,
    email,
    password: hashedPassword,
    isAdm,
    createdOn: dateNow,
    updatedOn: dateNow,
    uuid: uuidv4(),
  };
  users.push(newUser);

  return newUser;
};

const listUsersService = () => {
  return users;
};

const userLoginService = (email, password) => {
  const user = users.find((element) => element.email === email);

  if (!user) {
    return { message: "Email ou senha invalida" };
  }

  const passwordMatch = bcrypt.compareSync(password, user.password);

  if (passwordMatch === false) {
    return { message: "Email ou senha invalida" };
  }

  const token = jwt.sign(
    { email: email, id: user.uuid, isAdm: user.isAdm },
    "SECRET_KEY",
    { expiresIn: "24h" }
  );

  return { token: token };
};

const profileUserService = () => {
  return users;
};

const updateUserService = async (name, email, password, id) => {
  const userIndex = users.findIndex((element) => element.uuid === id);

  if (userIndex === -1) {
    return "User not found";
  }

  const dateNow = new Date();
  const hashedPassword = await bcrypt.hash(users[userIndex].password, 10);

  const updateUser = {
    name: name === undefined ? (name = users[userIndex].name) : name,
    email: email === undefined ? (email = users[userIndex].email) : email,
    password:
      password === undefined
        ? (password = users[userIndex].password)
        : hashedPassword,
    updatedOn: dateNow,
    createdOn: users[userIndex].createdOn,
    uuid: id,
    isAdm: users[userIndex].isAdm,
  };

  users[userIndex] = { ...users[userIndex], ...updateUser };

  return users[userIndex];
};

const deleteUserService = () => {
  return users;
};

const createUserController = async (request, response) => {
  const { name, email, password, isAdm } = request.body;

  const { password: removedPassword, ...user } = await createUserService(
    name,
    email,
    password,
    isAdm
  );

  return response.status(201).json(user);
};

const listUserController = (request, response) => {
  const user = listUsersService();

  if (request.isAdm !== true) {
    return response.status(403).json({ message: "missing admin permissions" });
  }
  return response.status(200).json(user);
};

const userLoginController = (request, response) => {
  const { email, password } = request.body;
  const userLogin = userLoginService(email, password);

  if (userLogin.message === "Email ou senha invalida") {
    return response.status(401).json(userLogin);
  }

  return response.json(userLogin);
};

const profileUserController = (request, response) => {
  const userProfile = profileUserService();
  const { password, ...user } = userProfile.find(
    (element) => element.email === request.userEmail
  );

  if (user == undefined) {
    return response.status(401).json("usuario invalido");
  }
  return response.status(200).json(user);
};

const updateUserController = async (request, response) => {
  const id = request.params.id;

  const { name, email, password } = request.body;

  const { password: removedPassword, ...updateUser } = await updateUserService(
    name,
    email,
    password,
    id
  );

  return response.json(updateUser);
};

const deleteUserController = (request, response) => {
  const id = request.params.id;
  const userProfile = deleteUserService();

  const userIndex = userProfile.findIndex((element) => element.uuid === id);
  if (userProfile[userIndex].uuid === id) {
    userProfile.splice(userIndex, 1);
    return response.status(204).json({ message: "User deleted with success" });
  } else if (request.isAdm === true) {
    userProfile.splice(userIndex, 1);
    return response.status(204).json({ message: "User deleted with success" });
  } else {
    return response.status(401).json({ message: "Missing admin permissions" });
  }
};

app.get("/users", verifyIsAdmMiddleware, verifyAuthToken, listUserController);
app.post("/users", verifyEmailAvailabilityMiddleware, createUserController);
app.get("/users/profile", verifyAuthToken, profileUserController);
app.patch(
  "/users/:id",
  verifyAuthToken,
  verifyIsAdmMiddleware,
  updateUserController
);
app.delete(
  "/users/:id",
  verifyAuthToken,
  verifyIsAdmMiddleware,
  deleteUserController
);
app.post("/login", userLoginController);

app.listen(PORT, () => {
  console.log(`server is running at port ${PORT}`);
});

export default app;
