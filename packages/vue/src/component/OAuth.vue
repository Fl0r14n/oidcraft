<template>
  <VNoSsr>
    <VMenu
      v-model="menu"
      rounded
      :close-on-content-click="false"
      location="bottom"
    >
      <template v-slot:activator="{ props }">
        <VBtn
          v-bind="props"
          :icon="isAuthorized ? mdiAccount : mdiAccountOutline"
        />
      </template>
      <VCard>
        <template v-if="isAuthorized">
          <slot
            name="userInfo"
            :user="user"
            :logout="signOut"
            v-if="$slots.userInfo"
          />
          <template v-else>
            <VList v-if="user?.name || user?.email">
              <VListItem v-bind="{ ...(user.name && { title: user.name }), ...(user.email && { subtitle: user.email }) }">
                <template #prepend>
                  <VAvatar color="primary">
                    <VImg :src="user.picture" v-if="user.picture" />
                    <span class="text-h5" v-else v-html="user.initials" />
                  </VAvatar>
                </template>
              </VListItem>
            </VList>
          </template>
          <VCardActions>
            <VSpacer />
            <VBtn @click="signOut()">{{ t("$vuetify.oauth.logout") }}</VBtn>
          </VCardActions>
        </template>
        <template v-else>
          <template v-if="error">
            <VCardText>
              <VAlert type="error" closable :text="error" @click:close="dismissError()" />
            </VCardText>
          </template>
          <template v-else>
            <template v-if="responseType && responseType !== OAuthType.RESOURCE">
              <VCardActions>
                <VSpacer />
                <VBtn @click="login(props as OAuthParameters)">
                  {{ t("$vuetify.oauth.login") }}
                </VBtn>
              </VCardActions>
            </template>
            <template v-else>
              <VForm autocomplete="on" @submit.prevent="submit()" @keyup.enter="submit()">
                <VCardText class="pb-0 oauth-form" style="min-width: 300px">
                  <VTextField
                    name="username"
                    required
                    autocomplete="username"
                    :prepend-inner-icon="mdiEmailOutline"
                    :label="t('$vuetify.oauth.username')"
                    :counter="length"
                    v-model="username"
                    :error-messages="usernameMessages"
                  />
                  <VTextField
                    name="password"
                    required
                    autocomplete="current-password"
                    :prepend-inner-icon="mdiLockOutline"
                    :append-inner-icon="passwordVisible ? mdiEyeOff : mdiEye"
                    :type="passwordVisible ? 'text' : 'password'"
                    :label="t('$vuetify.oauth.password')"
                    :counter="length"
                    v-model="password"
                    :error-messages="passwordMessages"
                    @click:append-inner="togglePasswordVisible()"
                  />
                </VCardText>
                <VCardActions>
                  <VSpacer />
                  <VBtn type="submit" :disabled="!valid || submitting">
                    {{ t("$vuetify.oauth.login") }}
                  </VBtn>
                </VCardActions>
              </VForm>
            </template>
          </template>
        </template>
      </VCard>
    </VMenu>
  </VNoSsr>
</template>
<script setup lang="ts">
import { mdiAccount, mdiAccountOutline, mdiEmailOutline, mdiEye, mdiEyeOff, mdiLockOutline } from '@mdi/js'
import type { OAuthParameters } from '@oidcraft/core'
import { computed, shallowRef, watch } from 'vue'
import { OAuthType, useOAuth, useOAuthForm, useOAuthUser } from 'vue-oidc'
import { useLocale } from 'vuetify'
import {
  VAlert,
  VAvatar,
  VBtn,
  VCard,
  VCardActions,
  VCardText,
  VForm,
  VImg,
  VList,
  VListItem,
  VMenu,
  VNoSsr,
  VSpacer,
  VTextField
} from 'vuetify/components'

const length = 128
const { t } = useLocale()
const { login, logout, isAuthorized } = useOAuth()
const user = useOAuthUser()
// Repeated from ./props rather than imported: @vue/compiler-sfc cannot resolve an imported type
// without filesystem access, which it refuses under Bun. ./props fails the typecheck if these drift.
const props = defineProps<{
  username?: string
  password?: string
  accessType?: 'online' | 'offline'
  prompt?: 'none' | 'consent' | 'login' | 'select_account'
  redirectUri?: string
  responseType?: string
  state?: string
  extras?: Record<string, string | undefined>
  logoutRedirectUri?: string
}>()
const menu = shallowRef(false)

const { username, password, errors, showErrors, valid, submitting, error, dismissError, passwordVisible, togglePasswordVisible, submit } =
  useOAuthForm({ username: props.username, password: props.password, maxLength: length })

// the composable reports a code; the wording is this component's, and its locale's
const messagesFor = (field: 'username' | 'password') =>
  computed(() => {
    if (!showErrors.value[field]) return []
    const code = errors.value[field]
    if (code === 'required') return [t(`$vuetify.oauth.${field}Required`)]
    if (code === 'tooLong') return [t(`$vuetify.oauth.${field}Length`, [length])]
    return []
  })

const usernameMessages = messagesFor('username')
const passwordMessages = messagesFor('password')

const signOut = async () => {
  menu.value = false
  await logout(props.logoutRedirectUri)
}

watch(
  user,
  () => {
    if (user.value) {
      const { given_name, family_name } = user.value
      if (given_name || family_name) {
        user.value.initials = `${given_name?.charAt(0) || ''}${family_name?.charAt(0) || ''}`
      } else {
        user.value.initials = `?`
      }
    }
  },
  { immediate: true }
)
</script>
