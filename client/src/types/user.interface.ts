import type { ICompany } from "@/service/company.service";
export interface ICompanyUser {
    id: string;
    name: string;
    avatarUrl: string;
    role: string
}
export interface IUser {
    id: number;
    username: string;
    email: string;
    avatarUrl: string;
    name: string;
    last_name: string;
    companies: ICompanyUser[]
}