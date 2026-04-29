import { axiosWithAuth } from "@/api/api.interceptors";
import type { ICreateOrder, IOrder, IOrderDataUpdate, IOrderUpdate, IPropertyOrderStatus } from "@/types/order.interface";

export const orderService = {
    async createOrder(companyId: number, orderData: ICreateOrder) {
        const { data } = await axiosWithAuth.post<ICreateOrder>(`company/${companyId}/orders`, { ...orderData, status: "NEW" })
        return data;
    },
    async getOrdersByCompany(companyId: number) {
        const { data } = await axiosWithAuth.get<IOrder[]>(`/company/${companyId}/orders`)
        return data;
    },
    async getOrderById(orderId: number) {
        const { data } = await axiosWithAuth.get<IOrder>(`/order/${orderId}`)// ----
        return data;
    },
    async updateOrder(orderId: number, data: IOrderDataUpdate) {
        const { data: responseData } = await axiosWithAuth.put<IOrderUpdate>(`/order/${orderId}`, data)
        return responseData;
    },
    async deleteOrder(orderId: number) {
        const { data: responseData } = await axiosWithAuth.delete(`order/${orderId}`);
        return responseData;
    },
    async addPropertyToOrder(orderId: number, propertyIds: number[]) {
        const { data: responseData } = await axiosWithAuth.put<IOrder>(`/order/${orderId}/properties`, propertyIds)// ----
        return responseData;
    },
    async getOrdersProperty(orderId: number) {
        const { data } = await axiosWithAuth.get<IOrder[]>(`/order/${orderId}/properties`)
        return data;
    },
    async updateOrderPropertyStatus(orderId: number, propertyId: number, status: IPropertyOrderStatus) {
        const { data: responseData } = await axiosWithAuth.put<IOrder>(`/order/${orderId}/${propertyId}/order-property`, status)
        return responseData;
    },
}
