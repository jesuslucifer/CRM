import { userService } from "@/service/user.service";
import { useQuery, useQueryClient } from "@tanstack/react-query";

export function useProfile(){
    const queryClient = useQueryClient()
    const {data: user, isLoading } = useQuery({
        queryKey: ['profile'],
        queryFn: () => userService.getProfile(),
    })
    return {user, isLoading}
}