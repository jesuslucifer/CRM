import type { IUser } from "./user.interface";

export interface ICreateCompany {
    name: string;
}
export interface ICompany {
    name: string;
}
export interface IEmployees extends IUser {

    role: string
}
export interface ICreateEmployee {
    email: string;
    role: string
}

export interface ICompanyById {
    id: number;
    name: string;
    avatar?: string

    employees: IEmployees[]
}