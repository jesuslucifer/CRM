import type { ILoginRequest, IRegisterRequest, JwtResponse, SuccessResponse } from "@/types/auth.interface"
import { getRefreshToken, removeFromStorage, saveTokensStorage } from "./auth-token.service"
import { axiosClassic } from "@/api/api.interceptors"
import {   useNavigate } from "react-router"
 
export const authService = {
  async login(data: ILoginRequest): Promise<JwtResponse> {
    const response = await axiosClassic.post<JwtResponse>("/auth/login", data, {
      withCredentials: true
    })
    
    const { accessToken, refreshToken } = response.data
    saveTokensStorage(accessToken, refreshToken)

    return response.data
  },

  async register(data: IRegisterRequest): Promise<SuccessResponse> {
    return axiosClassic.post<SuccessResponse>("/auth/sign-up", data, {
      withCredentials: true
    }).then(res => res.data)
  },

  async refresh(): Promise<JwtResponse> {
    const refreshToken = getRefreshToken()
    if (!refreshToken) throw new Error("No refresh token")
    const response = await axiosClassic.post<JwtResponse>("/auth/refresh", { refreshToken }, {
      withCredentials: true
    })
    const { accessToken, refreshToken: newRefreshToken } = response.data
    saveTokensStorage(accessToken, newRefreshToken)
    return response.data
  },

  async logout() {
    removeFromStorage()
    
    // const response = await axiosClassic.post<SuccessResponse>("/auth/logout", null, {
    //   withCredentials: true
    // })

    // return response.data
  }
}
