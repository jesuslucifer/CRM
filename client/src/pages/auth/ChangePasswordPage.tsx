import { Button } from "@/components/ui/button"
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { useChangePassword, useForgotPassword } from "@/shared/hooks/useUser"
import { useForm } from "react-hook-form"
export default function ChangePasswordPage() {
    const form = useForm({ mode: "onChange" });
    const { onSubmit, isPending } = useChangePassword();

    return (
        <div className="bg-white rounded-3xl border shadow-sm p-8">
            <h2 className="text-xl font-semibold mb-2">Смена пароля</h2>
            <p className="text-sm text-slate-500 mb-6">
                Используйте надежный пароль длиной не менее 8 символов
            </p>

            <Form {...form}>
                <form
                    className="space-y-5"
                    onSubmit={form.handleSubmit((data) =>
                        onSubmit(data.currentPassword, data.newPassword)
                    )}
                >
                    <FormField
                        control={form.control}
                        name="currentPassword"
                        render={({ field }) => (
                            <FormItem>
                                <FormLabel>Текущий пароль</FormLabel>
                                <FormControl>
                                    <Input
                                        type="password"
                                        placeholder="••••••••"
                                        {...field}
                                        value={field.value || ""}
                                        className="h-11 rounded-xl"
                                    />
                                </FormControl>
                                <FormMessage />
                            </FormItem>
                        )}
                    />

                    <FormField
                        control={form.control}
                        name="newPassword"
                        render={({ field }) => (
                            <FormItem>
                                <FormLabel>Новый пароль</FormLabel>
                                <FormControl>
                                    <Input
                                        type="password"
                                        placeholder="••••••••"
                                        {...field}
                                        value={field.value || ""}
                                        className="h-11 rounded-xl"
                                    />
                                </FormControl>
                                <FormMessage />
                            </FormItem>
                        )}
                    />

                    <Button
                        type="submit"
                        disabled={isPending}
                        className="w-full h-11 rounded-xl bg-black text-white hover:bg-slate-800 transition"
                    >
                        {isPending ? "Сохранение..." : "Обновить пароль"}
                    </Button>
                </form>
            </Form>
        </div>
    );
}