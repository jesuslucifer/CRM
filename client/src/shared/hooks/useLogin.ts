// import { authService } from "@/service/auth.service";
// import { useMutation, useQueryClient } from "@tanstack/react-query";

// export const useLogin = () => {
//   const queryClient = useQueryClient();

//   return useMutation({
//     mutationFn: ({ usernameOrEmail, password }: { usernameOrEmail: string; password: string }) =>
//       authService.login(usernameOrEmail, password),
//     onSuccess: () => {
//       queryClient.invalidateQueries({ queryKey: ["profile"] });
//     },
//   });
// };
