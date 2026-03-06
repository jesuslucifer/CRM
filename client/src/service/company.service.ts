import { axiosWithAuth } from "@/api/api.interceptors"
import type { IUser } from "@/types/user.interface";
 
const API_URL = '/company';
export interface ICreateCompany {
    name: string;
}
export interface ICompany {
    name: string;
}
export interface IEmployees {
 user: IUser
    role: string
}

export interface ICompanyById {
    id:  number;
    name: string;
    avatar?: string
    
    employees: IEmployees[]
}
export const CompanyService = {
    async createCompany(payload: ICreateCompany) {
        const {data} = await axiosWithAuth.post<ICreateCompany>(API_URL + '/create', payload);
        return data;
    },
    async getCompanyList() {
        const {data} = await axiosWithAuth.get<ICompany[]>(API_URL + '/list');
        return data;
    },
    async getCompanyById(id: number) {
        const {data} = await axiosWithAuth.get<ICompanyById>(API_URL + `/${id}`);
        return data;
    }
}