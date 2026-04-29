import { axiosWithAuth } from "@/api/api.interceptors"
import type { IClient, IClientResponse } from "@/types/client.interface";

export const ClientsService = {
    async createClient(companyId: number, clientData: IClient) {
        const { data } = await axiosWithAuth.post<IClient>(`company/${companyId}/clients`, clientData);
        return data;
    },
    async getCompanyClient(companyId: number) {
        const { data } = await axiosWithAuth.get<IClientResponse[]>(`company/${companyId}/clients`);
        return data;
    }
}