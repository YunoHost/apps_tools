# Providing prebuilt archive within Yunohost packages

## Table of content
- [Why using a prebuilt archive in an app package ?](#why-using-a-prebuilt-archive-in-an-app-package-)
- [How to build the app and distribute the resulting files](#how-to-build-the-app-and-distribute-the-resulting-files)
  * [1. Local build by the package maintainer](#1-local-build-by-the-package-maintainer)
  * [2. Cloud build using Github Actions in the app package's repository](#2-cloud-build-using-github-actions-in-the-app-packages-repository)
  * [3. [someday™?] Cloud build using Yunohost's own infrastructure](#3-someday-cloud-build-using-yunohosts-own-infrastructure)
- [To-do list](#to-do-list)
- [Contribute](#contribute)

<a name="why-using-a-prebuilt-archive-in-an-app-package-"></a>
## Why using a prebuilt archive in an app package ?
YunoHost strives to **be as efficient as possible in terms of resources usage** in order to be used on old and/or low-end hardware.
Therefore YunoHost packagers generally use a prebuilt archive when available upstream instead of building the app locally at installation (thus saving the least beefy hardware from the build effort and providing a smoother installation process).

However in some cases:
1. There are no prebuilt archive available upstream (e.g. [it-tools_ynh](https://github.com/Yunohost-Apps/it-tools_ynh));
2. Upstream prebuilt archive does not suit the Yunohost package: it may contain antifeatures that can be easily removed when building the app (e.g. removing tracking such as Google Analytics & Sentry, remove intrusive calls to switch to a closed-source premium cloud-based product like in [jsoncrack_ynh](https://github.com/YunoHost-Apps/jsoncrack_ynh/blob/f529e13fc8ad75347b2859e2ec66e728676f7416/scripts/build#L30)), it may not support subpath installation unless performing a custom build it (e.g. [cinny_ynh](https://github.com/YunoHost-Apps/cinny_ynh/pull/98)), etc;
3. You do not trust prebuilt archive and are afraid of [supply-chain attacks](https://en.wikipedia.org/wiki/Supply_chain_attack).

To address those cases **as a YunoHost packager**, you may typically want to build the app locally, adding instructions for it in `scripts/install` and `scripts/upgrade`.
But some technologies (like NodeJS) require a **disproportionate amount of resources** (e.g. heavy CPU use, several GB of RAM and disk space) **to build a given app compared to what it takes to run the app** once it is built (e.g. that much for an app that may eventually run client-side and therefore consume near-zero CPU time, RAM and minimal storage needs on the server hosting it - i.e. it could be hosted on every hardware).
Consequently the building step could be the only obstacle preventing from installing such app on old and/or low-end hardware.

Several approaches can tackle this issue although they all boil down to the same principle: have one actor building the app files from upstream source and then host it online where `install` and `upgrade` scripts will point to.
YunoHost instance admins finding themselves in the more extreme case 3 above may be happy with some of the approaches proposed which are auditable to some extent, or more radically prefer sticking with local build.

<a name="how-to-build-the-app-and-distribute-the-resulting-files"></a>
## How to build the app and distribute the resulting files

There are several methods currently in use and you may chose the one you prefer.
The most convenient one for now may be the second one described below.

<a name="1-local-build-by-the-package-maintainer"></a>
### 1. Local build by the package maintainer
The package maintainer builds the app on his/her machine and upload the resuting files to the Github Releases section of the package's repository.

<a name="proscons"></a>
#### Pros/Cons
- **Pro**: Easy to move (if YunoHost happens to come to selfhost its packages' repository in the future) since GitHub is only used as a distribution channel (the build part being independant form it).
- **Con**: The app packager is required to have the adequate available hardware to perform the build.
- **Con**: Despite open-sourcing of the build scripts, there can't really be transparency on the build action itself, so YunoHost instance admins must trust the packager that the app files were not tampered during build time.

<a name="what-to-do"></a>
#### What to do
This is the first approach used historically among YunoHost apps and may take different forms.
An interesting example is the one created by [Josue-T](https://github.com/Josue-T) which is used so far to maintain [synapse_ynh](https://github.com/YunoHost-Apps/synapse_ynh). The build and upload processes are being automatized by the following scripts the maintainer runs via a Cron job on a personal machine:
- https://github.com/YunoHost-Apps/synapse_ynh/tree/master/auto_update
- https://github.com/YunoHost-Apps/synapse_python_build

<a name="2-cloud-build-using-github-actions-in-the-app-packages-repository"></a>
### 2. Cloud build using Github Actions in the app package's repository
This may be the most convenient method currently available for package maintainers. It is currently used by several app packages:
- [it-tools_ynh](https://github.com/Yunohost-Apps/it-tools_ynh) 
- [jsoncrack_ynh](https://github.com/Yunohost-Apps/jsoncrack_ynh)
- [fossflow_ynh](https://github.com/Yunohost-Apps/fossflow_ynh)

<a name="proscons-1"></a>
#### Pros/Cons
- **Pro**: No cost and no hardware requirement for the either the package maintainer or the YunoHost project.
- **Pro**: Build process is auditable (build log, time, file checksum availables) provided you are logged into GitHub.
- **Con**: Relies fully on GitHub, so the latter should be trusted (although that may impact only quite advanced threat models).
- **Con**: Might not always be free of direct costs.

<a name="what-to-do-1"></a>
#### What to do
All required templates mentioned in this section are [available there](https://github.com/oleole39/prebuild-app).
To set it up, you will need to:
1. **Copy the file `scripts/build`** in your package's repository and adapt the "SECTION TO EDIT" as follows:
    - **Variables**: Adjust variables' content to fit your package. Everything should be filled in, except `gh_personal_token` which can remain empty.
    - **[*optional*] Source customization**: if some of the upstream source files need to be customized before build (for instance to allow subpath install or to remove some antifeatures), you can add related commands here.
    - **Build instructions**: add required build commands here.
2. **Make sure `manifest.toml` has the two following resources** declared (of course there can be more in addition to them):
    - `main` , which will only be used by YunoHost's autoupdater script to check whether a new version is available upstream.
    - `ynh_build`, which points to the prebuilt archive to use as the main source archive in `install` and `upgrade` scripts. Note that `url` and `sha256` field can initially contain dummy content as they will be automatically updated as soon as a build workflow will run successfully.

    Here is an example:
    ```toml
    [resources]

        [resources.sources]

            [resources.sources.main]
            # This is not used as we are using git clone. It's only here for autoupdate.
            url = "https://github.com/AykutSarac/jsoncrack.com/archive/6c5a4f4db79f0b97ec90e8b5b206caacbdaeda64.tar.gz"
            sha256 = "438af1ca5d1813850a12a453c87a62175c71ad75f1be09a698de2f578fb345bf"
            prefetch = false
            autoupdate.strategy = "latest_github_commit"

            [resources.sources.ynh_build]
            url = "https://github.com/Yunohost-Apps/jsoncrack_ynh/releases/download/v2025.05.25-6c5a4f4d/jsoncrack.com_v2025.05.25-6c5a4f4d_ynh.zip"
            sha256 = "733ccc6fc437befb770a6ad5752b0ebf0957528fd2a57bdc0213bdfbda15324c"
            format = "zip"
            extract = true
            in_subdir = true
    ```
3. **Copy workflows files to `/.github/workflows/` in your package's repository** (or only the ones you want - generally at least "on-demand" and "on-upstream-update"), in which you would have **tailored the second step (e.g. "Setup Node.js") to your needs** (than can mean changing Node version, or using another runtime environment than Node.js crafting your own adequate action - feel free to submit a PR to add a template to this repo).
Three kinds of template workflows are available:
    - **`ynh-build-on-demand.yml`** runs when you manually trigger it on a selected branch of your package's repository.
    - **`ynh-build-on-upstream-update.yml`** runs when a pull request is created by YunoHost autoupdate bot (yunohost-bot) according to the `autoupdate.stragegy` declared in the `manifest.toml` - generally in `[resources.sources.main]`.
    Basically, at every update notified by Yunohost autoupdate bot, this workflow will attempt a build from the new upstream source files, store it as a draft release and update `url` and `sha256` fields for `ynh_build` source in manifest in the PR branch. That is to say that at every upstream release, the maintenance work will be limited to the following steps:
        - Only if you added custom commands in the the optional Source customizations section of the `build` script, to check new upstream commits to make sure your customizations are not broken (or if so push changes to the `build` script and trigger the workflow manually to create a new build). Anyway, if a cutomization is broken here and that's you don't detect it via the upstream commits history, you will likely see it while testing the upgrade.
        - Publish the new release (currently in draft status) in the release section.

        Only after these steps you can expect to test successfully the release via the CI and manual install before merging the upgrade PR.
    - **`ynh-build-on-push-to-testing.yml`** runs at every push to the branch `testing`. This workflow can be helpful when creating the initial package and that you need to iterate many builds to get a first one actually fuilly working. However, you would generally disable it (or you can remove it from your package's repository).

4. **Make sure `/scripts/install` and `/scripts/ugprade` use `ynh_setup_source` helper with the `source_id` flag corresponding to the prebuilt archive** as declared in the `manifest.toml` in point 2 above (e.g. `ynh_setup_source --dest_dir="$install_dir" --source_id="ynh_build"`).

<a name="things-to-know-when-using-the-workflows"></a>
#### Things to know when using the workflows
- All workflows added to a repository are enabled by default. **To prevent a workflow to execute automatically** while not removing it, you can disable it in the Actions tab of the package's repository (provided you have write access to the latter):
    1. Select the the workflow to disable in the left sidebar.
    2. Click on the button containing three dots nearby the "Filter workflow runs" input box on the top right.
    3. Click on "Disable workflow" (at the same place will then be the button "Enable workflow" for if you want to re-enable it later on).
- When one of these workflows is running, it creates at some point a draft release. However **[it doesn't check whether there already exists a published release of the same name](https://github.com/softprops/action-gh-release/issues/74)**. Consequently, if there was already a published release of the same name, the latter would get unpublished and given a draft status and its content (PR body and attachment) overwritten with the ones just generated by the workflow, resulting in an interruption of service for the install scripts given that the package are pointing to a resource which does not existing anymore.
    - This scenario should never happen with `ynh-build-on-upstream-update.yml` given that it is meant to always build a new version of the app.
    - But it is likely to happen if you try to rebuild an already published release with one of the other workflows.
    - Would that happen to you, you will want to publish a new version of the package for the same upstream version contaning updated URL in `manifest.toml` ( `[resources.sources.ynh_build]`) bumping the `~ynh` version number so that YunoHost instances' admins who installed that app are not left with a broken package on their server.

<a name="3-someday-cloud-build-using-yunohosts-own-infrastructure"></a>
### 3. [someday™?] Cloud build using Yunohost's own infrastructure
The method would be similar to the previous one, but would use Yunohost infrastructure via custom scripts or a self-hosted forge. However this does not exist yet... Maybe someday™.

<a name="proscons-2"></a>
#### Pros/Cons:
- **Pro**: Independance from GitHub.
- **Pro**: Build process (could be made) auditable (build log, time, file checksum availables).
- **Con**: Additional maintenance work for the YunoHost project.
- **Con**: Potential additional infrastructure costs for the YunoHost project.

<a name="to-do-list"></a>
## To-do list
- [ ] Harmonize with @Josue-T script for synapse which is already in production so that we ideally have a single common template to make it easier for packagers.
- [ ] Add support for other sources than Github URL
- [ ] Add support for multi-arch apps
- [ ] Tweak YNH core to offer a choice at install between prebuilt archive (if available) or local build.

<a name="to-do-list"></a>
## Contribute
You can contribute via this repository or for a more general discussion about prebuilding files in YunoHost [check the related issue in YunohHost's issue tracker](https://github.com/YunoHost/issues/issues/2281)
