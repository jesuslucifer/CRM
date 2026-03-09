// api/interceptors.ts
import { getAccessToken, removeFromStorage } from "@/service/auth-token.service";
import { authService } from "@/service/auth.service";
import axios from "axios";

const options = {
  baseURL: "http://localhost:8080/api",
  headers: { "Content-Type": "application/json" },
  withCredentials: true,
};

export const axiosClassic = axios.create(options);
export const axiosWithAuth = axios.create(options);

// Добавляем accessToken в каждый запрос
axiosWithAuth.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (config.headers && token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Обновление токена при 401
axiosWithAuth.interceptors.response.use(
  (res) => res,
  async (error) => {
    const originalRequest = error.config;

    if (
      (error.response?.status === 401) &&
      !originalRequest._isRetry // чтобы не зациклиться
    ) {
      originalRequest._isRetry = true;
      try {
        await authService.refresh();
        return axiosWithAuth.request(originalRequest); // повторяем запрос
      } catch (err) {
        removeFromStorage();
        window.location.href = "/login"; // редирект на логин
      }
    }

    return Promise.reject(error);
  }
);
