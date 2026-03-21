import { axiosWithAuth } from "@/api/api.interceptors";
import type { ICreateOrder, IOrder } from "@/types/order.interface";

export const orderService = {
    async createOrder(companyId: number, orderData: ICreateOrder) {
        const { data } = await axiosWithAuth.post<ICreateOrder>(`company/${companyId}/order/create`, orderData)
        return data;
    },
    async getOrdersByCompany(companyId: number) {
        const { data } = await axiosWithAuth.get<IOrder[]>(`/company/${companyId}/orders`)
        return data;
    }
}