import { prisma } from "../config/prismaClient";
import { Response, Request } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";

const generateToken = (userId: string, email: string, role: string) => {
  const accessToken = jwt.sign(
    {
      userId,
      email,
      role,
    },
    process.env.JWT_SECRET!,
    { expiresIn: "60m" }
  );
  const refreshToken = uuidv4();
  return { accessToken, refreshToken };
};

const setTokens = async (
  res: Response,
  accessToken: string,
  refreshToken: string
) => {
  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 60 * 60 * 1000,
  });
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60,
  });
};

export const signUp = async (req: Request, res: Response): Promise<void> => {
  try {
    const { name, email, password } = req.body;
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      res.status(400).json({
        success: false,
        error: "User already exists",
      });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await prisma.user.create({
      data: { email, name, password: hashedPassword, role: "USER" },
    });
    res.status(201).json({
      success: true,
      message: "User created successfully",
      userId: user.id,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Request failed." });
  }
};

export const signIn = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;
    const currentUser = await prisma.user.findUnique({ where: { email } });
    if (!currentUser) {
      res.status(401).json({
        success: false,
        error: "Invalid credentials",
      });
      return;
    }
    const isValidPassword = await bcrypt.compare(
      password,
      currentUser!.password
    );
    if (!isValidPassword) {
      res.status(401).json({
        success: false,
        error: "Invalid credentials",
      });
      return;
    }
    const { accessToken, refreshToken } = generateToken(
      currentUser.id,
      currentUser.email,
      currentUser.role
    );
    await setTokens(res, accessToken, refreshToken);
    res.status(200).json({
      success: true,
      message: "User logged in successfully",
      user: {
        id: currentUser.id,
        name: currentUser.name,
        email: currentUser.email,
        role: currentUser.role,
      },
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Sign in failed." });
  }
};

export const refreshAccessToken = async (
  req: Request,
  res: Response
): Promise<void> => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    res.status(401).json({
      success: false,
      error: "Invalid refresh token",
    });
    return;
  }
  try {
    const user = await prisma.user.findUnique({
      where: { refreshToken: refreshToken },
    });
    if (!user) {
      res.status(401).json({
        success: false,
        error: "User not found",
      });
      return;
    }
    const { accessToken, refreshToken: newRefreshToken } = generateToken(
      user.id,
      user.email,
      user.role
    );
    await setTokens(res, accessToken, newRefreshToken);
    res.status(200).json({
      success: true,
      message: "Refresh token success",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Refresh token error" });
  }
};

export const signOut = async (req: Request, res: Response): Promise<void> => {
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.status(200).json({ success: true, message: "Sign out successfully" });
};
