import { axiosWithAuth } from "@/api/api.interceptors"
import type { ICompany, ICompanyById, ICreateCompany, ICreateEmployee } from "@/types/company.interface";
import type { IUser } from "@/types/user.interface";

const API_URL = '/company';

export const CompanyService = {
    async createCompany(payload: ICreateCompany) {
        const { data } = await axiosWithAuth.post<ICreateCompany>(API_URL + '/create', payload);
        return data;
    },
    async getCompanyList() {
        const { data } = await axiosWithAuth.get<ICompany[]>(API_URL + '/list');
        return data;
    },
    async getCompanyById(id: number) {
        const { data } = await axiosWithAuth.get<ICompanyById>(API_URL + `/${id}`);
        return data;
    },
    async createCompanyEmployee(id: number, payload: ICreateEmployee) {
        const { data } = await axiosWithAuth.put<ICreateEmployee>(API_URL + `/${id}/employees`, payload);
        return data;
    },
    async deleteCompanyEmployee(companyId: number, employeeId: number) {
        const { data } = await axiosWithAuth.delete(API_URL + `/${companyId}/${employeeId}/employees`);
        return data;
    }
}