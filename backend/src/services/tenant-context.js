import { AsyncLocalStorage } from 'async_hooks';

export const tenantStorage = new AsyncLocalStorage();

export function currentTenantId() {
  return tenantStorage.getStore()?.organizationId || null;
}

export function tenantSettingKey() {
  const id = currentTenantId();
  return id ? `organization:${id}` : 'global';
}

export function withTenant(organizationId, fn) {
  return tenantStorage.run({ organizationId: String(organizationId) }, fn);
}

export function tenantPlugin(schema) {
  schema.add({ organization: { type: schema.base.Schema.Types.ObjectId, ref: 'Organization', index: true } });

  // Mongoose 9 pre middleware no longer supplies the legacy `next` callback.
  // These hooks are synchronous, so completing the function advances the middleware chain.
  schema.pre('validate', function() {
    const tenantId = currentTenantId();
    if (tenantId && !this.organization) this.organization = tenantId;
  });

  const queryHook = function() {
    const tenantId = currentTenantId();
    if (tenantId && !this.getOptions()?.bypassTenant) {
      const query = this.getQuery();
      if (!Object.prototype.hasOwnProperty.call(query, 'organization')) this.where({ organization: tenantId });
    }
  };

  ['find','findOne','countDocuments','updateOne','updateMany','deleteOne','deleteMany','findOneAndUpdate','findOneAndDelete','findOneAndReplace'].forEach(hook => schema.pre(hook, queryHook));

  schema.pre('aggregate', function() {
    const tenantId = currentTenantId();
    if (tenantId && !this.options?.bypassTenant) {
      this.pipeline().unshift({ $match: { organization: new schema.base.Types.ObjectId(String(tenantId)) } });
    }
  });
}
