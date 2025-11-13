import { useState, useEffect } from "react";
import { supabase } from "@/integrations/supabase/client";
import type { AuthError } from "@supabase/supabase-js";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { toast } from "sonner";
import { CheckCircle2, Loader2, AlertTriangle, X } from "lucide-react";
import { authSchema } from "@/schemas/auth.schema";
import { z } from "zod";

export const Auth = () => {
  const [isSignUp, setIsSignUp] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [validationSuggestion, setValidationSuggestion] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      if (session) {
        navigate("/");
      }
    });

    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session) {
        navigate("/");
      }
    });

    return () => subscription.unsubscribe();
  }, [navigate]);

  const getErrorMessage = (e: unknown): string => {
    if (e instanceof Error) return e.message;
    if (
      typeof e === "object" &&
      e !== null &&
      "message" in e &&
      typeof (e as { message?: unknown }).message === "string"
    ) {
      return (e as { message: string }).message;
    }
    return "An unexpected error occurred.";
  };

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setValidationSuggestion(null);

    try {
      // Validate input with zod
      const validated = authSchema.parse({ email, password });
      const normalizedEmail = validated.email;

      if (isSignUp) {
        const { error } = await supabase.auth.signUp({
          email: normalizedEmail,
          password,
          options: {
            emailRedirectTo: `${window.location.origin}/`,
          },
        });
        if (error) {
          const message: string = error?.message ?? "Signup failed";
          const details: string | undefined = (error as AuthError & { details?: string })?.details;

          // Try to extract a suggested email from known error formats
          let suggested: string | null = null;
          const didYouMeanMatch = message.match(/Did you mean\s+([^?\s]+)\?/i);
          if (didYouMeanMatch && didYouMeanMatch[1]) {
            suggested = didYouMeanMatch[1].trim().toLowerCase();
          }
          if (!suggested && details) {
            const detailMatch = details.match(/did_you_mean=([^,\s]+)/i);
            if (detailMatch && detailMatch[1]) {
              suggested = detailMatch[1].trim().toLowerCase();
            }
          }

          if (suggested && suggested !== normalizedEmail) {
            setValidationSuggestion(suggested);
            setLoading(false);
            return;
          }

          // Fallback: if GoTrue hides DB error as "unexpected_failure",
          // ask the validator directly so we can surface a helpful message
          const errorCode = (error as AuthError).code;
          const looksGeneric =
            errorCode === "unexpected_failure" || /Database error saving new user/i.test(message);
          if (looksGeneric) {
            try {
              const { data, error: rpcError } = await supabase.rpc(
                "validate_email_with_zerobounce",
                { p_email: normalizedEmail }
              );
              if (!rpcError && data) {
                const result = data as unknown as {
                  valid: boolean;
                  email: string;
                  status?: string;
                  sub_status?: string;
                  did_you_mean?: string;
                  message?: string;
                };

                if (result.did_you_mean && result.did_you_mean !== normalizedEmail) {
                  setValidationSuggestion(result.did_you_mean);
                  setLoading(false);
                  return;
                }
                if (result.valid === false) {
                  toast.error("We couldn't verify this email. Please check and try again.");
                  setLoading(false);
                  return;
                }
              }
            } catch (_) {
              // Ignore and fall back to default error handling
            }
          }

          throw error;
        }
        toast.success("Account created! You can now sign in.");
        setIsSignUp(false);
      } else {
        const { error } = await supabase.auth.signInWithPassword({
          email: normalizedEmail,
          password,
        });
        if (error) throw error;
      }
    } catch (error: unknown) {
      if (error instanceof z.ZodError) {
        toast.error(error.errors[0].message);
      } else {
        toast.error(isSignUp ? "Signup failed. Please try again." : "Sign in failed. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  const useSuggestion = () => {
    if (validationSuggestion) {
      setEmail(validationSuggestion);
      setValidationSuggestion(null);
    }
  };

  const dismissSuggestion = () => {
    setValidationSuggestion(null);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4" style={{ background: "var(--gradient-subtle)" }}>
      <Card className="w-full max-w-md shadow-lg border-border/50" style={{ boxShadow: "var(--shadow-medium)" }}>
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ background: "var(--gradient-primary)" }}>
              <CheckCircle2 className="w-7 h-7 text-white" />
            </div>
          </div>
          <CardTitle className="text-2xl font-bold bg-clip-text text-transparent" style={{ backgroundImage: "var(--gradient-primary)" }}>
            {isSignUp ? "Create account" : "Welcome back"}
          </CardTitle>
          <CardDescription>
            {isSignUp
              ? "Enter your email to create your account"
              : "Enter your credentials to access your todos"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {validationSuggestion && (
            <Alert aria-live="polite" className="mb-4 border-amber-300/60 bg-amber-50/80 text-amber-900 shadow-sm dark:border-amber-400/40 dark:bg-amber-950/30 dark:text-amber-200">
              <AlertTriangle className="h-4 w-4 text-amber-500 dark:text-amber-400" />
              <AlertDescription className="flex items-center justify-between gap-3">
                <div className="text-sm">
                  <span className="opacity-90">Did you mean: </span>
                  <button
                    type="button"
                    onClick={useSuggestion}
                    className="font-semibold underline decoration-amber-400 underline-offset-2 hover:opacity-80"
                  >
                    {validationSuggestion}
                  </button>
                  <span>?</span>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={useSuggestion}
                    className="border-amber-300 text-amber-900 hover:bg-amber-100 dark:border-amber-400 dark:text-amber-100 dark:hover:bg-amber-900/40"
                  >
                    Use this
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    aria-label="Dismiss suggestion"
                    onClick={dismissSuggestion}
                    className="text-amber-700 hover:bg-amber-100 dark:text-amber-200 dark:hover:bg-amber-900/40"
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              </AlertDescription>
            </Alert>
          )}
          <form onSubmit={handleAuth} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="transition-all duration-200 focus:shadow-soft"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={6}
                className="transition-all duration-200 focus:shadow-soft"
              />
            </div>
            <Button
              type="submit"
              className="w-full hover:opacity-90 transition-opacity"
              disabled={loading}
              style={{ background: "var(--gradient-primary)" }}
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Please wait
                </>
              ) : isSignUp ? (
                "Sign up"
              ) : (
                "Sign in"
              )}
            </Button>
          </form>
          <div className="mt-4 text-center text-sm">
            <button
              type="button"
              onClick={() => setIsSignUp(!isSignUp)}
              className="text-muted-foreground hover:text-primary transition-colors"
            >
              {isSignUp ? "Already have an account? Sign in" : "Don't have an account? Sign up"}
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
