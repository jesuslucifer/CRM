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
export interface IClientResponse {
    id: number,
    firstName: string,
    lastName: string,
    phone: number,
    email: string,
    clientType: string,
    clientSource: string,
    notes: string
}
export const ClientsService = {
    async createClient(companyId: number, clientData: IClient) {
        const { data } = await axiosWithAuth.post<IClient>(`company/${companyId}/client/create`, clientData);
        return data;
    },
    async getCompanyClient(companyId: number) {
        const { data } = await axiosWithAuth.get<IClientResponse[]>(`company/${companyId}/clients`);
        return data;
    }
}