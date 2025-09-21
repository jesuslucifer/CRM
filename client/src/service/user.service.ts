import { axiosWithAuth } from "@/api/api.interceptors"
import type { IUser } from "@/types/user.interface";

export const userService = {
    async getProfile(){
        const {data} = await axiosWithAuth.get<IUser>('/users/me')
        return data;
    }
}
