export interface ILoginRequest {
  usernameOrEmail: string
  password: string
}

export interface IRegisterRequest {
  username: string
  email: string
  password: string
}

export interface JwtResponse {
  accessToken: string
  refreshToken: string
}

export interface SuccessResponse {
  message: string
  status: string
}
