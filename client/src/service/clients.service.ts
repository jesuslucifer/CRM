import { axiosWithAuth } from "@/api/api.interceptors"
export interface IClient {
    firstName: string,
    lastName: string,
    phone: number,
    email: string,
    clientType: string,
    clientSource: string,
    notes: string
}
export const ClientsService = {
    async createClient(companyId: number) {
        const { data } = await axiosWithAuth.post<IClient>(`company/${companyId}/client/create`);
        return data;
    }
}