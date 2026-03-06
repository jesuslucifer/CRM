import { axiosWithAuth } from "@/api/api.interceptors"
import type { IChangeEmail, IForgotPassword } from "@/shared/hooks/useUser";
import type { IUser } from "@/types/user.interface";
export interface IChangePassword{
    currentPassword: string,
    newPassword: string
}
export const userService = {
    async getProfile(){
        const {data} = await axiosWithAuth.get<IUser>('/users/me')
        return data;
    },
    async getUserById(id: number){
        const {data} = await axiosWithAuth.get<IUser>(`/users/${id}`)
        return data;
    },
    async getAllUsers(){
        const {data} = await axiosWithAuth.get<IUser[]>(`/users`)
        return data;
    },
    async forgotPassword(email: IForgotPassword){
        const {data} = await axiosWithAuth.post<IForgotPassword>('/users/forgot-password',email)
        return data
    },
     async changePassword(password: IChangePassword){
        const {data} = await axiosWithAuth.post<IChangePassword>('/users/change-password',password )
        return data
    },
      async changeEmail(emailData: IChangeEmail){
        const {data} = await axiosWithAuth.post<IChangeEmail>('/users/change-email',emailData)
        return data
    }
}
